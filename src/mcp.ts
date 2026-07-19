import { loadConfig } from "./config.js";
import { TokenValidationError } from "./oauth/tokenValidator.js";
import { createGenericOidcValidator } from "./adapters/generic-oidc.js";
import { createAuth0Validator } from "./adapters/auth0.js";
import { createWorkosValidator } from "./adapters/workos.js";
import { YamlPolicyEngine } from "./policy/engine.js";
import { FileAuditSink, hashArguments } from "./audit/logger.js";
import { WebhookStepUpProvider } from "./stepup/webhook.js";
import { buildAuthorizationRequest } from "./proxy/authorization-request.js";
import { UpstreamManager } from "./proxy/upstream.js";
import type { JsonRpcRequest, JsonRpcResponse } from "./types/jsonrpc.js";

// ---------------------------------------------------------------------------
// Config & Bootstrapping
// ---------------------------------------------------------------------------

const CONFIG_PATH = process.env.LIMEKEY_CONFIG ?? "./limekey.config.yaml";
const config = loadConfig(CONFIG_PATH);

function buildTokenValidator(cfg: typeof config) {
  switch (cfg.identity.provider) {
    case "auth0":
      return createAuth0Validator(cfg);
    case "workos":
      return createWorkosValidator(cfg);
    case "generic_oidc":
    default:
      return createGenericOidcValidator(cfg);
  }
}

const tokenValidator = buildTokenValidator(config);
const policyEngine = new YamlPolicyEngine(config.policy.source);
const auditSink = new FileAuditSink(config.audit.path);
const stepUp = config.step_up
  ? new WebhookStepUpProvider(
      config.step_up.webhook_url,
      config.step_up.timeout_seconds,
      config.step_up.on_timeout,
      config.step_up.webhook_secret,
    )
  : null;

// ---------------------------------------------------------------------------
// JSON-RPC Transport & Buffer
// ---------------------------------------------------------------------------

let buffer = "";
const MAX_BUFFER_SIZE = 10 * 1024 * 1024; // 10MB maximum buffer limit to prevent OOM DoS (T0-4)

function listenToStdin() {
  process.stdin.on("data", (chunk) => {
    buffer += chunk.toString("utf-8");

    if (buffer.length > MAX_BUFFER_SIZE) {
      buffer = ""; // Clear buffer to prevent OOM
      process.stderr.write("[limekey] MCP buffer limit exceeded (10MB max). Resetting to prevent OOM.\n");
      return;
    }

    let newlineIndex;
    while ((newlineIndex = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, newlineIndex).trim();
      buffer = buffer.slice(newlineIndex + 1);
      if (line) {
        handleLine(line).catch((err) => {
          sendError(null, -32603, `Internal handler error: ${(err as Error).message}`);
        });
      }
    }
  });
}

interface ParsedRequest {
  jsonrpc: "2.0";
  id?: number | string | null;
  method: string;
  params?: unknown;
}

async function handleLine(line: string) {
  let req: ParsedRequest;
  try {
    req = JSON.parse(line) as ParsedRequest;
  } catch {
    sendError(null, -32700, "Parse error: Invalid JSON");
    return;
  }

  if (req.jsonrpc !== "2.0") {
    sendError(req.id ?? null, -32600, "Invalid Request: jsonrpc version must be 2.0");
    return;
  }

  const { id, method, params } = req;

  // Notifications (no id) — forward in proxy mode, handle known ones in standalone
  if (id === undefined || id === null) {
    if (method === "notifications/initialized") return; // handshake complete
    // In proxy mode, forward other notifications
    if (upstream) {
      upstream.send({ jsonrpc: "2.0", id: null, method, params }, requestTimeoutMs)
        .catch(() => {}); // ignore output as notifications don't return anything
    }
    return;
  }

  // ---------------------------------------------------------------------------
  // Proxy mode: intercept tools/call, forward everything else
  // ---------------------------------------------------------------------------
  if (upstream) {
    await handleProxyRequest(id, method, params, line);
    return;
  }

  // ---------------------------------------------------------------------------
  // Standalone mode: handle the authorize tool directly
  // ---------------------------------------------------------------------------
  await handleStandaloneRequest(id, method, params);
}

// ---------------------------------------------------------------------------
// Proxy Mode
// ---------------------------------------------------------------------------

let upstream: UpstreamManager | null = null;
const requestTimeoutMs = (config.upstream?.request_timeout ?? 30) * 1000;

async function handleProxyRequest(
  clientId: number | string,
  method: string,
  params: unknown,
  _rawLine: string,
) {
  if (method === "initialize") {
    // Return cached initialize result to be fully spec-compliant and avoid
    // sending a second initialize to the upstream.
    const result = upstream ? upstream.getInitializeResult() : null;
    writeStdout({
      jsonrpc: "2.0",
      id: clientId,
      result,
    });
    return;
  }

  if (method !== "tools/call") {
    // Forward all non-intercepted methods transparently
    try {
      const upstreamRes = await upstream!.send(
        { jsonrpc: "2.0", id: clientId, method, params },
        requestTimeoutMs,
      );
      // Restore the client's original ID before writing back
      writeStdout({ ...upstreamRes, id: clientId });
    } catch (err) {
      sendError(clientId, -32603, `Upstream error: ${(err as Error).message}`);
    }
    return;
  }

  // -------------------------------------------------------------------------
  // tools/call — intercept and enforce policy
  // -------------------------------------------------------------------------
  const start = Date.now();
  const paramsObj = params as Record<string, unknown> | null | undefined;

  if (!paramsObj || typeof paramsObj !== "object") {
    sendError(clientId, -32602, "Invalid params: params must be an object");
    return;
  }

  const toolName = paramsObj.name;
  if (typeof toolName !== "string" || !toolName) {
    sendError(clientId, -32602, "Invalid params: name must be a non-empty string");
    return;
  }

  const toolArgs =
    paramsObj.arguments && typeof paramsObj.arguments === "object"
      ? (paramsObj.arguments as Record<string, unknown>)
      : {};

  // Token extraction — in MCP proxy mode the agent passes it as an argument
  const rawToken = toolArgs.token ?? (paramsObj.token);
  const bearerToken =
    typeof rawToken === "string" ? rawToken.replace(/^Bearer\s+/i, "") : null;

  if (!bearerToken) {
    sendToolResult(clientId, { error: "missing_token", message: "Bearer token is required." }, true);
    return;
  }

  const sessionId = typeof toolArgs.session_id === "string" ? toolArgs.session_id : undefined;

  // Token validation
  let validated: { agentId: string; principal: string };
  try {
    validated = await tokenValidator.validate(bearerToken, sessionId);
  } catch (err) {
    if (err instanceof TokenValidationError) {
      sendToolResult(clientId, { error: err.code, message: err.message }, true);
      return;
    }
    sendError(clientId, -32603, `Token validation error: ${(err as Error).message}`);
    return;
  }

  // Build canonical AuthorizationRequest
  const authReq = buildAuthorizationRequest(
    validated.agentId,
    validated.principal,
    toolName,
    toolArgs,
  );

  // Policy evaluation
  const policyResult = await policyEngine.evaluate(authReq);

  let finalDecision = policyResult.decision;
  let stepUpOutcome: { requested: boolean; approved?: boolean } | null = null;

  if (policyResult.decision === "step_up") {
    if (!stepUp) {
      finalDecision = "deny";
      process.stderr.write(`[limekey-proxy] Step-up requested for tool "${authReq.tool}" but no step_up provider is configured. Falling back to deny.\n`);
    } else {
      stepUpOutcome = { requested: true };
      const outcome = await stepUp.requestApproval({
        agentId: authReq.principal.agentId,
        principal: authReq.principal.sub,
        toolName: authReq.tool,
        argumentsSummary: JSON.stringify(authReq.arguments).slice(0, 500),
      });
      stepUpOutcome.approved = outcome === "approved";
      finalDecision = outcome === "approved" ? "allow" : "deny";
    }
  }

  // Audit every decision
  await auditSink.write({
    request_id: authReq.requestId,
    ts: authReq.timestamp,
    agent_id: authReq.principal.agentId,
    principal: authReq.principal.sub,
    tool_name: authReq.tool,
    arguments_hash: hashArguments(authReq.arguments),
    decision: finalDecision,
    matched_rule: policyResult.matchedRule,
    step_up: stepUpOutcome,
    latency_ms: Date.now() - start,
  });

  if (finalDecision === "deny") {
    // Return MCP-native tool error — upstream never sees this request
    sendProxyDenial(clientId, authReq.requestId, policyResult.matchedRule);
    return;
  }

  // ALLOW — forward to upstream, pipe response back to client
  try {
    const upstreamRes = await upstream!.send(
      { jsonrpc: "2.0", id: clientId, method: "tools/call", params },
      requestTimeoutMs,
    );
    writeStdout({ ...upstreamRes, id: clientId });
  } catch (err) {
    await auditSink.write({
      request_id: authReq.requestId,
      ts: new Date().toISOString(),
      agent_id: authReq.principal.agentId,
      principal: authReq.principal.sub,
      tool_name: authReq.tool,
      arguments_hash: hashArguments(authReq.arguments),
      decision: "upstream_failure",
      matched_rule: null,
      step_up: null,
      latency_ms: Date.now() - start,
    });
    sendError(clientId, -32603, `Upstream failure: ${(err as Error).message}`);
  }
}

// ---------------------------------------------------------------------------
// Standalone Mode — authorize tool (backward compatible)
// ---------------------------------------------------------------------------

async function handleStandaloneRequest(
  id: number | string,
  method: string,
  params: unknown,
) {
  switch (method) {
    case "initialize":
      sendResponse(id, {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "limekey-mcp", version: "0.1.0" },
      });
      break;

    case "ping":
      sendResponse(id, {});
      break;

    case "tools/list":
      sendResponse(id, {
        tools: [
          {
            name: "authorize",
            description:
              "Authorize an AI agent's tool execution check against Limekey policies. Returns allow or deny.",
            inputSchema: {
              type: "object",
              properties: {
                token: {
                  type: "string",
                  description:
                    "Bearer access token representing the user and agent (without the 'Bearer ' prefix is also fine)",
                },
                tool_name: {
                  type: "string",
                  description: "The name of the tool to be authorized",
                },
                arguments: {
                  type: "object",
                  description: "The arguments payload to be passed to the tool",
                },
                session_id: {
                  type: "string",
                  description:
                    "Optional session identifier for tracking the chat history session",
                },
              },
              required: ["token", "tool_name"],
            },
          },
        ],
      });
      break;

    case "tools/call": {
      const paramsObj = params as Record<string, unknown> | null | undefined;
      if (!paramsObj || typeof paramsObj !== "object") {
        sendError(id, -32602, "Invalid params: params must be an object");
        break;
      }
      if (paramsObj.name !== "authorize") {
        sendToolResult(
          id,
          { error: "unknown_tool", message: `Unknown tool: ${paramsObj.name}` },
          true,
        );
        break;
      }
      await handleAuthorizeToolCall(id, paramsObj.arguments);
      break;
    }

    default:
      sendError(id, -32601, `Method not found: ${method}`);
  }
}

async function handleAuthorizeToolCall(id: number | string, args: unknown) {
  if (!args || typeof args !== "object") {
    sendError(id, -32602, "Invalid params: arguments object is required");
    return;
  }

  const a = args as Record<string, unknown>;
  const rawToken = a.token;
  const toolName = a.tool_name;

  if (typeof rawToken !== "string" || !rawToken) {
    sendToolResult(id, { error: "missing_token", message: "Bearer token is required." }, true);
    return;
  }

  if (typeof toolName !== "string" || !toolName) {
    sendToolResult(
      id,
      { error: "invalid_body", message: "tool_name must be a non-empty string." },
      true,
    );
    return;
  }

  const bearerToken = rawToken.replace(/^Bearer\s+/i, "");
  const toolArgs =
    a.arguments && typeof a.arguments === "object"
      ? (a.arguments as Record<string, unknown>)
      : {};
  const sessionId = typeof a.session_id === "string" ? a.session_id : undefined;

  const start = Date.now();

  let validated: { agentId: string; principal: string };
  try {
    validated = await tokenValidator.validate(bearerToken, sessionId);
  } catch (err) {
    if (err instanceof TokenValidationError) {
      sendToolResult(id, { error: err.code, message: err.message }, true);
      return;
    }
    sendError(id, -32603, `Token validation error: ${(err as Error).message}`);
    return;
  }

  const authReq = buildAuthorizationRequest(
    validated.agentId,
    validated.principal,
    toolName,
    toolArgs,
    sessionId,
  );

  const result = await policyEngine.evaluate(authReq);
  let finalDecision = result.decision;
  let stepUpOutcome: { requested: boolean; approved?: boolean } | null = null;

  if (result.decision === "step_up") {
    if (!stepUp) {
      finalDecision = "deny";
      process.stderr.write(`[limekey-proxy] Step-up requested for tool "${authReq.tool}" but no step_up provider is configured. Falling back to deny.\n`);
    } else {
      stepUpOutcome = { requested: true };
      const outcome = await stepUp.requestApproval({
        agentId: authReq.principal.agentId,
        principal: authReq.principal.sub,
        toolName: authReq.tool,
        argumentsSummary: JSON.stringify(authReq.arguments).slice(0, 500),
      });
      stepUpOutcome.approved = outcome === "approved";
      finalDecision = outcome === "approved" ? "allow" : "deny";
    }
  }

  await auditSink.write({
    request_id: authReq.requestId,
    ts: authReq.timestamp,
    agent_id: authReq.principal.agentId,
    principal: authReq.principal.sub,
    tool_name: authReq.tool,
    arguments_hash: hashArguments(authReq.arguments),
    decision: finalDecision,
    matched_rule: result.matchedRule,
    step_up: stepUpOutcome,
    latency_ms: Date.now() - start,
  });

  if (finalDecision === "allow") {
    sendToolResult(id, { decision: "allow" });
  } else {
    sendToolResult(id, {
      decision: "deny",
      matched_rule: result.matchedRule,
      reason: `Operation denied by policy rule: "${result.matchedRule}"`,
    }, true);
  }
}

// ---------------------------------------------------------------------------
// Output Utilities
// ---------------------------------------------------------------------------

function sendResponse(id: number | string, result: unknown) {
  writeStdout({ jsonrpc: "2.0", id, result } as JsonRpcResponse);
}

function sendToolResult(
  id: number | string,
  data: Record<string, unknown>,
  isError = false,
) {
  sendResponse(id, {
    content: [{ type: "text", text: JSON.stringify(data) }],
    isError,
  });
}

function sendError(
  id: number | string | null,
  code: number,
  message: string,
) {
  writeStdout({
    jsonrpc: "2.0",
    id,
    error: { code, message },
  } as JsonRpcResponse);
}

/** Policy denial response — MCP-native isError with explainability. */
function sendProxyDenial(id: number | string, requestId: string, matchedRule: string) {
  sendResponse(id, {
    content: [
      {
        type: "text",
        text: `Operation denied by LimeKey policy rule: "${matchedRule}".`,
      },
    ],
    isError: true,
    _meta: { request_id: requestId, matched_rule: matchedRule },
  });
}

function writeStdout(msg: JsonRpcRequest | JsonRpcResponse | Record<string, unknown>) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

// ---------------------------------------------------------------------------
// Startup & Initialization
// ---------------------------------------------------------------------------

async function start() {
  // 1. Initialize audit sink
  await auditSink.init?.();

  // 2. Start proxy/upstream if configured
  if (config.upstream) {
    const startupTimeoutMs = config.upstream.startup_timeout * 1000;
    upstream = new UpstreamManager(config.upstream);

    let reconnectAttempts = 0;
    let isReconnecting = false;

    const handleUpstreamCrash = () => {
      if (isReconnecting) return;
      isReconnecting = true;

      // Exponential backoff reconnect: 1s, 2s, 4s, 8s, up to 15s max (T1-3)
      const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 15000);
      reconnectAttempts++;

      process.stderr.write(`[limekey-proxy] upstream crashed — attempting reconnect in ${delay}ms (attempt ${reconnectAttempts})\n`);

      setTimeout(async () => {
        try {
          upstream = new UpstreamManager(config.upstream!);
          upstream.on("crash", handleUpstreamCrash);
          await upstream.start(startupTimeoutMs);
          process.stderr.write("[limekey-proxy] upstream successfully reconnected!\n");
          reconnectAttempts = 0;
          isReconnecting = false;
        } catch (err) {
          isReconnecting = false;
          handleUpstreamCrash();
        }
      }, delay);
    };

    upstream.on("crash", handleUpstreamCrash);

    await upstream.start(startupTimeoutMs);
    process.stderr.write("[limekey-proxy] upstream ready, accepting client connections\n");
  }

  // 3. Start listening to stdin
  listenToStdin();
}

start().catch((err) => {
  process.stderr.write(`[limekey] failed to start: ${err}\n`);
  process.exit(1);
});

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

function shutdown() {
  Promise.all([
    upstream?.shutdown(),
    auditSink.close?.(),
  ])
    .catch(() => {})
    .finally(() => {
      process.exit(0);
    });
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
