import { loadConfig } from "./config.js";
import { TokenValidationError } from "./oauth/tokenValidator.js";
import { createGenericOidcValidator } from "./adapters/generic-oidc.js";
import { createAuth0Validator } from "./adapters/auth0.js";
import { createWorkosValidator } from "./adapters/workos.js";
import { YamlPolicyEngine } from "./policy/engine.js";
import type { ToolCall } from "./policy/types.js";
import { FileAuditSink, hashArguments } from "./audit/logger.js";
import { WebhookStepUpProvider } from "./stepup/webhook.js";

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
const stepUp = new WebhookStepUpProvider(
  config.step_up.webhook_url,
  config.step_up.timeout_seconds,
  config.step_up.on_timeout,
);

// Initialize audit sink immediately
auditSink.init?.().catch((err) => {
  process.stderr.write(`Failed to initialize audit sink: ${err}\n`);
});

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
        sendError(null, -32603, `Internal handler error: ${err.message}`);
      });
    }
  }
});

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: number | string | null;
  method: string;
  params?: any;
}

async function handleLine(line: string) {
  let req: JsonRpcRequest;
  try {
    req = JSON.parse(line) as JsonRpcRequest;
  } catch (err) {
    sendError(null, -32700, "Parse error: Invalid JSON");
    return;
  }

  if (req.jsonrpc !== "2.0") {
    sendError(req.id ?? null, -32600, "Invalid Request: jsonrpc version must be 2.0");
    return;
  }

  const { id, method, params } = req;

  // Handle Notifications (requests without an ID)
  if (id === undefined || id === null) {
    if (method === "notifications/initialized") {
      // Handshake completed — no response required
      return;
    }
    // Ignore other unhandled notifications
    return;
  }

  switch (method) {
    case "initialize":
      sendResponse(id, {
        protocolVersion: "2024-11-05",
        capabilities: {
          tools: {},
        },
        serverInfo: {
          name: "limekey-mcp",
          version: "0.1.0",
        },
      });
      break;

    case "tools/list":
      sendResponse(id, {
        tools: [
          {
            name: "authorize",
            description: "Authorize an AI agent's tool execution check against Limekey policies. Returns allow or deny.",
            inputSchema: {
              type: "object",
              properties: {
                token: {
                  type: "string",
                  description: "Bearer access token representing the user and agent (without the 'Bearer ' prefix is also fine)",
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
                  description: "Optional session identifier for tracking the chat history session",
                },
              },
              required: ["token", "tool_name"],
            },
          },
        ],
      });
      break;

    case "ping":
      sendResponse(id, {});
      break;

    case "tools/call":
      if (!params || typeof params !== "object") {
        sendError(id, -32602, "Invalid params: params must be an object");
        break;
      }
      if (params.name !== "authorize") {
        sendToolResult(id, { error: "unknown_tool", message: `Unknown tool: ${params.name}` }, true);
        break;
      }
      await handleAuthorizeToolCall(id, params.arguments);
      break;

    default:
      sendError(id, -32601, `Method not found: ${method}`);
  }
}

async function handleAuthorizeToolCall(id: number | string, args: any) {
  if (!args || typeof args !== "object") {
    sendError(id, -32602, "Invalid params: arguments object is required");
    return;
  }

  const rawToken = args.token;
  const toolName = args.tool_name;

  if (typeof rawToken !== "string" || !rawToken) {
    sendToolResult(id, { error: "missing_token", message: "Bearer token is required." }, true);
    return;
  }

  if (typeof toolName !== "string" || !toolName) {
    sendToolResult(id, { error: "invalid_body", message: "tool_name must be a non-empty string." }, true);
    return;
  }

  const bearerToken = rawToken.replace(/^Bearer\s+/i, "");
  const toolArgs = args.arguments && typeof args.arguments === "object" ? args.arguments : {};
  const sessionId = typeof args.session_id === "string" ? args.session_id : undefined;

  const start = Date.now();

  // Validate Access Token
  let validated;
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

  // Construct Tool Call Context
  const call: ToolCall = {
    agentId: validated.agentId,
    principal: validated.principal,
    resource: config.server.resource_id,
    toolName,
    arguments: toolArgs,
    context: { ts: new Date().toISOString(), sessionId },
  };

  // Evaluate Policies
  const result = await policyEngine.evaluate(call);
  let finalDecision = result.decision;
  let stepUpOutcome: { requested: boolean; approved?: boolean } | null = null;

  // Handle step-up approvals if triggered
  if (result.decision === "step_up") {
    stepUpOutcome = { requested: true };
    const outcome = await stepUp.requestApproval({
      agentId: call.agentId,
      principal: call.principal,
      toolName: call.toolName,
      argumentsSummary: JSON.stringify(call.arguments).slice(0, 500),
    });
    stepUpOutcome.approved = outcome === "approved";
    finalDecision = outcome === "approved" ? "allow" : "deny";
  }

  // Write Audit Event
  await auditSink.write({
    ts: call.context.ts,
    agent_id: call.agentId,
    principal: call.principal,
    resource: call.resource,
    tool_name: call.toolName,
    arguments_hash: hashArguments(call.arguments),
    decision: finalDecision,
    matched_rule: result.matchedRule,
    step_up: stepUpOutcome,
    latency_ms: Date.now() - start,
  });

  // Respond with Decision
  if (finalDecision === "allow") {
    sendToolResult(id, { decision: "allow" });
  } else {
    sendToolResult(id, { decision: "deny", rule: result.matchedRule });
  }
}

// ---------------------------------------------------------------------------
// Output Utilities
// ---------------------------------------------------------------------------

function sendResponse(id: number | string, result: any) {
  const payload = {
    jsonrpc: "2.0",
    id,
    result,
  };
  process.stdout.write(JSON.stringify(payload) + "\n");
}

function sendToolResult(id: number | string, data: Record<string, unknown>, isError = false) {
  sendResponse(id, {
    content: [
      {
        type: "text",
        text: JSON.stringify(data),
      },
    ],
    isError,
  });
}

function sendError(id: number | string | null, code: number, message: string) {
  const payload = {
    jsonrpc: "2.0",
    id,
    error: {
      code,
      message,
    },
  };
  process.stdout.write(JSON.stringify(payload) + "\n");
}

// Handle termination signals cleanly
function shutdown() {
  auditSink.close?.().finally(() => {
    process.exit(0);
  });
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
