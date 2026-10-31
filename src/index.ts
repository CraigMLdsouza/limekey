import Fastify from "fastify";
import rateLimit from "@fastify/rate-limit";
import { loadConfig, parseListenAddress } from "./config.js";
import {
  buildResourceMetadata,
  resourceMetadataHandler,
} from "./oauth/resourceMetadata.js";
import { TokenValidationError } from "./oauth/tokenValidator.js";
import { createGenericOidcValidator } from "./adapters/generic-oidc.js";
import { createAuth0Validator } from "./adapters/auth0.js";
import { createWorkosValidator } from "./adapters/workos.js";
import { YamlPolicyEngine } from "./policy/engine.js";
import { FileAuditSink, hashArguments } from "./audit/logger.js";
import { WebhookStepUpProvider } from "./stepup/webhook.js";
import { buildAuthorizationRequest } from "./proxy/authorization-request.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const CONFIG_PATH = process.env.LIMEKEY_CONFIG ?? "./limekey.config.yaml";
const config = loadConfig(CONFIG_PATH);
const { host, port } = parseListenAddress(config.server.listen);

// ---------------------------------------------------------------------------
// Identity — pick the right adapter based on config.identity.provider
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Policy, audit, step-up
// ---------------------------------------------------------------------------

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
// App
// ---------------------------------------------------------------------------

const app = Fastify({
  logger: {
    redact: {
      paths: [
        "req.headers.authorization",
        "headers.authorization",
        "body.token",
        "body.arguments.token",
      ],
      censor: "[REDACTED]",
    }
  },
  bodyLimit: 1048576, // 1MB payload size limit to prevent OOM (T0-4)
});

await app.register(rateLimit, {
  max: 100, // Limit each IP to 100 requests per minute to prevent API flooding (T0-4)
  timeWindow: "1 minute",
});

// --- Global error handler ---------------------------------------------------

app.setErrorHandler(async (error: any, _req, reply) => {
  app.log.error(error);
  const statusCode = (error as { statusCode?: number }).statusCode ?? 500;
  return reply.code(statusCode).send({
    error: statusCode >= 500 ? "internal_error" : "bad_request",
    message:
      statusCode >= 500
        ? "An unexpected error occurred."
        : error.message,
  });
});

// --- CORS -------------------------------------------------------------------
// Allow browser-based MCP clients and agent UIs to call discovery + authorize.

app.addHook("onRequest", async (req, reply) => {
  reply.header("Access-Control-Allow-Origin", "*");
  reply.header(
    "Access-Control-Allow-Methods",
    "GET, POST, OPTIONS",
  );
  reply.header(
    "Access-Control-Allow-Headers",
    "Authorization, Content-Type",
  );
  if (req.method === "OPTIONS") {
    return reply.code(204).send();
  }
});

// --- Health check -----------------------------------------------------------

app.get("/health", async () => {
  return { status: "ok", version: "0.1.0" };
});

// --- RFC 9728 discovery endpoint --------------------------------------------
// Lets MCP clients find the right authorization server before they ever
// get a token.

app.get("/.well-known/oauth-protected-resource", async () => {
  return resourceMetadataHandler(
    buildResourceMetadata({
      resourceId: config.server.resource_id,
      authorizationServerIssuer: config.identity.issuer,
    }),
  );
});

// --- Authorization decision endpoint ----------------------------------------
// Every tool call an agent makes flows through this single decision point.

app.post("/v0/authorize", async (req, reply) => {
  const start = Date.now();

  // --- Request body validation & extraction ---
  const body = req.body as Record<string, unknown> | null | undefined;
  if (!body || typeof body !== "object") {
    return reply.code(400).send({
      error: "invalid_body",
      message: "Request body must be a JSON object.",
    });
  }

  const toolName = body.tool_name;
  if (typeof toolName !== "string" || toolName.length === 0) {
    return reply.code(400).send({
      error: "invalid_body",
      message: "\"tool_name\" is required and must be a non-empty string.",
    });
  }

  const args =
    body.arguments != null && typeof body.arguments === "object"
      ? (body.arguments as Record<string, unknown>)
      : {};

  const sessionId =
    typeof body.session_id === "string" ? body.session_id : undefined;

  // --- Token extraction & validation ---
  const authHeader = req.headers.authorization ?? "";
  if (!authHeader.toLowerCase().startsWith("bearer ")) {
    return reply.code(401).send({
      error: "missing_token",
      message: "Authorization header with Bearer token is required.",
    });
  }
  const bearerToken = authHeader.replace(/^Bearer\s+/i, "");

  let validated;
  try {
    validated = await tokenValidator.validate(bearerToken, sessionId);
  } catch (err) {
    if (err instanceof TokenValidationError) {
      return reply.code(401).send({ error: err.code, message: err.message });
    }
    throw err;
  }

  // --- Policy evaluation ---
  const authReq = buildAuthorizationRequest(
    validated.agentId,
    validated.principal,
    toolName,
    args,
    sessionId,
  );

  const result = await policyEngine.evaluate(authReq);
  let finalDecision = result.decision;
  let stepUpOutcome: { requested: boolean; approved?: boolean } | null = null;

  if (result.decision === "step_up") {
    if (!stepUp) {
      finalDecision = "deny";
      app.log.warn(`Step-up requested for tool "${authReq.tool}" but no step_up provider is configured. Falling back to deny.`);
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

  // --- Audit (always, regardless of outcome) ---
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
    return reply.code(200).send({ decision: "allow" });
  }
  return reply.code(403).send({
    decision: "deny",
    matched_rule: result.matchedRule,
    reason: `Operation denied by policy rule: "${result.matchedRule}"`,
  });
});

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

async function start() {
  // Bootstrap audit sink (creates directories, etc.)
  await auditSink.init();

  await app.listen({ host, port });
}

start().catch((err) => {
  app.log.error(err);
  process.exit(1);
});

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------

async function shutdown(signal: string) {
  app.log.info(`received ${signal}, shutting down…`);
  await app.close();
  await auditSink.close();
  process.exit(0);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
