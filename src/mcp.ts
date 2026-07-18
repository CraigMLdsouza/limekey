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
    )
  : null;

// Initialize audit sink immediately
auditSink.init?.().catch((err) => {
  process.stderr.write(`Failed to initialize audit sink: ${err}\n`);
});

// ---------------------------------------------------------------------------
// Task Scoped Session Store
// ---------------------------------------------------------------------------

interface TaskContext {
  taskId: string;
  subject: string;
  agentId: string;
  createdAt: Date;
  expiresAt: Date;
  requestCount: number;
}

class TaskStore {
  private readonly tasks = new Map<string, TaskContext>();

  create(agentId: string, subject: string, ttlSeconds: number): TaskContext {
    const taskId = `task_${Math.random().toString(36).substring(2, 15)}`;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);
    const task: TaskContext = {
      taskId,
      agentId,
      subject,
      createdAt: now,
      expiresAt,
      requestCount: 0,
    };
    this.tasks.set(taskId, task);
    return task;
  }

  lookup(taskId: string): TaskContext | undefined {
    this.cleanupExpired();
    return this.tasks.get(taskId);
  }

  delete(taskId: string): void {
    this.tasks.delete(taskId);
  }

  cleanupExpired(): void {
    const now = new Date();
    for (const [taskId, task] of this.tasks.entries()) {
      if (task.expiresAt <= now) {
        this.tasks.delete(taskId);
      }
    }
  }
}

const taskStore = new TaskStore();

async function handleMcpAuth(id: number | string, params: unknown) {
  const paramsObj = params as Record<string, unknown> | null | undefined;
  if (!paramsObj || typeof paramsObj !== "object") {
    sendError(id, -32602, "Invalid params: params must be an object");
    return;
  }

  const rawToken = paramsObj.token;
  if (typeof rawToken !== "string" || !rawToken) {
    sendError(id, -32602, "Invalid params: token must be a non-empty string");
    return;
  }

  const bearerToken = rawToken.replace(/^Bearer\s+/i, "");
  try {
    const validated = await tokenValidator.validate(bearerToken);
    const ttl = config.identity.task_ttl_seconds ?? 60;
    const task = taskStore.create(validated.agentId, validated.principal, ttl);
    sendResponse(id, {
      authenticated: true,
      task_id: task.taskId,
    });
  } catch (err) {
    if (err instanceof TokenValidationError) {
      sendError(id, -32652, `Authentication failed: ${err.message}`);
      return;
    }
    sendError(id, -32603, `Authentication error: ${(err as Error).message}`);
  }
}

// ---------------------------------------------------------------------------
// JSON-RPC Transport
// ---------------------------------------------------------------------------

let buffer = "";

process.stdin.on("data", (chunk) => {
  buffer += chunk.toString("utf-8");
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

  // Handle mcp_auth globally in both modes
  if (method === "mcp_auth") {
    if (id === undefined || id === null) {
      sendError(null, -32600, "Invalid Request: id is required for mcp_auth");
      return;
    }
    await handleMcpAuth(id, params);
    return;
  }

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

  const taskId = toolArgs.task_id ?? paramsObj.task_id;
  if (typeof taskId !== "string" || !taskId) {
    sendToolResult(clientId, { error: "missing_task_id", message: "task_id is required." }, true);
    return;
  }

  const task = taskStore.lookup(taskId);
  if (!task) {
    sendToolResult(clientId, { error: "unauthorized", message: "Task session not found or expired." }, true);
    return;
  }

  task.requestCount++;
  const maxRequests = config.identity.max_requests ?? 5;
  if (task.requestCount > maxRequests) {
    taskStore.delete(task.taskId);
    sendToolResult(clientId, { error: "task_expired", message: "Task request execution limit exceeded." }, true);
    return;
  }

  const validated = { agentId: task.agentId, principal: task.subject };

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
    task_id: task.taskId,
    request_count: task.requestCount,
  });

  if (finalDecision === "deny") {
    // Return MCP-native tool error — upstream never sees this request
    sendProxyDenial(clientId, authReq.requestId);
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
      task_id: task.taskId,
      request_count: task.requestCount,
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
  const taskId = a.task_id;
  const rawToken = a.token;
  const toolName = a.tool_name;

  if (typeof toolName !== "string" || !toolName) {
    sendToolResult(
      id,
      { error: "invalid_body", message: "tool_name must be a non-empty string." },
      true,
    );
    return;
  }

  const toolArgs =
    a.arguments && typeof a.arguments === "object"
      ? (a.arguments as Record<string, unknown>)
      : {};
  const sessionId = typeof a.session_id === "string" ? a.session_id : undefined;

  const start = Date.now();

  let validated: { agentId: string; principal: string };
  let currentTask: TaskContext | undefined;

  if (typeof taskId === "string" && taskId) {
    const task = taskStore.lookup(taskId);
    if (!task) {
      sendToolResult(id, { error: "unauthorized", message: "Task session not found or expired." }, true);
      return;
    }
    task.requestCount++;
    const maxRequests = config.identity.max_requests ?? 5;
    if (task.requestCount > maxRequests) {
      taskStore.delete(task.taskId);
      sendToolResult(id, { error: "task_expired", message: "Task request execution limit exceeded." }, true);
      return;
    }
    validated = { agentId: task.agentId, principal: task.subject };
    currentTask = task;
  } else if (typeof rawToken === "string" && rawToken) {
    const bearerToken = rawToken.replace(/^Bearer\s+/i, "");
    try {
      validated = await tokenValidator.validate(bearerToken);
    } catch (err) {
      if (err instanceof TokenValidationError) {
        sendToolResult(id, { error: err.code, message: err.message }, true);
        return;
      }
      sendError(id, -32603, `Token validation error: ${(err as Error).message}`);
      return;
    }
  } else {
    sendToolResult(id, { error: "missing_token", message: "Bearer token or task_id is required." }, true);
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
    task_id: currentTask?.taskId,
    request_count: currentTask?.requestCount,
  });

  if (finalDecision === "allow") {
    sendToolResult(id, { decision: "allow" });
  } else {
    // In standalone mode expose the decision only — no rule names in responses
    sendToolResult(id, { decision: "deny" }, true);
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

/** Policy denial response — MCP-native isError, minimal information. */
function sendProxyDenial(id: number | string, requestId: string) {
  sendResponse(id, {
    content: [
      {
        type: "text",
        text: "Operation denied by LimeKey policy.",
      },
    ],
    isError: true,
    _meta: { request_id: requestId },
  });
}

function writeStdout(msg: JsonRpcRequest | JsonRpcResponse | Record<string, unknown>) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

async function startProxy() {
  if (!config.upstream) return; // standalone mode — no upstream to start

  const startupTimeoutMs = config.upstream.startup_timeout * 1000;
  console.error("========== LIMEKEY UPSTREAM PASSED TO MANAGER ==========");
  console.error(JSON.stringify(config.upstream));
  console.error("========================================================");
  upstream = new UpstreamManager(config.upstream);

  upstream.on("crash", () => {
    process.stderr.write("[limekey-proxy] upstream crashed — shutting down\n");
    shutdown();
  });

  await upstream.start(startupTimeoutMs);
  process.stderr.write("[limekey-proxy] upstream ready, accepting client connections\n");
}

startProxy().catch((err) => {
  process.stderr.write(`[limekey-proxy] failed to start upstream: ${err}\n`);
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
