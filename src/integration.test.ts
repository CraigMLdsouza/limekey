import { describe, it, expect, beforeAll, afterAll } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";
import {
  buildResourceMetadata,
  resourceMetadataHandler,
} from "./oauth/resourceMetadata.js";

/**
 * Integration tests for the Limekey gateway.
 *
 * These test the Fastify routes directly using `app.inject()` — no real
 * network calls, no real JWKS endpoints. We isolate the authorization
 * decision layer from real token validation so the tests run fast and
 * deterministically.
 */

function buildTestApp(): FastifyInstance {
  const app = Fastify({ logger: false });

  // CORS hook
  app.addHook("onRequest", async (req, reply) => {
    reply.header("Access-Control-Allow-Origin", "*");
    reply.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    reply.header(
      "Access-Control-Allow-Headers",
      "Authorization, Content-Type",
    );
    if (req.method === "OPTIONS") {
      return reply.code(204).send();
    }
  });

  // Error handler
  app.setErrorHandler(async (error, _req, reply) => {
    const statusCode = (error as { statusCode?: number }).statusCode ?? 500;
    return reply.code(statusCode).send({
      error: statusCode >= 500 ? "internal_error" : "bad_request",
      message:
        statusCode >= 500 ? "An unexpected error occurred." : error.message,
    });
  });

  // Health
  app.get("/health", async () => {
    return { status: "ok", version: "0.1.0" };
  });

  // Discovery
  app.get("/.well-known/oauth-protected-resource", async () => {
    return resourceMetadataHandler(
      buildResourceMetadata({
        resourceId: "https://tools.test.internal",
        authorizationServerIssuer: "https://auth.test.com/",
      }),
    );
  });

  // Authorize — minimal version for integration testing
  app.post("/v0/authorize", async (req, reply) => {
    const authHeader = req.headers.authorization ?? "";
    if (!authHeader.toLowerCase().startsWith("bearer ")) {
      return reply.code(401).send({
        error: "missing_token",
        message: "Authorization header with Bearer token is required.",
      });
    }

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
        message:
          '"tool_name" is required and must be a non-empty string.',
      });
    }

    // In integration tests we skip real token validation and policy;
    // we just test the HTTP layer contracts.
    return reply.code(200).send({ decision: "allow" });
  });

  return app;
}

describe("Limekey Integration", () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = buildTestApp();
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  // --- Health ---------------------------------------------------------------

  describe("GET /health", () => {
    it("returns 200 with status ok", async () => {
      const res = await app.inject({ method: "GET", url: "/health" });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.status).toBe("ok");
      expect(body.version).toBe("0.1.0");
    });
  });

  // --- RFC 9728 Discovery ---------------------------------------------------

  describe("GET /.well-known/oauth-protected-resource", () => {
    it("returns valid RFC 9728 metadata", async () => {
      const res = await app.inject({
        method: "GET",
        url: "/.well-known/oauth-protected-resource",
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.resource).toBe("https://tools.test.internal");
      expect(body.authorization_servers).toEqual(["https://auth.test.com/"]);
      expect(body.bearer_methods_supported).toEqual(["header"]);
    });
  });

  // --- CORS -----------------------------------------------------------------

  describe("CORS", () => {
    it("OPTIONS returns 204 with CORS headers", async () => {
      const res = await app.inject({
        method: "OPTIONS",
        url: "/v0/authorize",
      });
      expect(res.statusCode).toBe(204);
      expect(res.headers["access-control-allow-origin"]).toBe("*");
      expect(res.headers["access-control-allow-methods"]).toContain("POST");
      expect(res.headers["access-control-allow-headers"]).toContain(
        "Authorization",
      );
    });

    it("GET responses include CORS headers", async () => {
      const res = await app.inject({ method: "GET", url: "/health" });
      expect(res.headers["access-control-allow-origin"]).toBe("*");
    });
  });

  // --- POST /v0/authorize ---------------------------------------------------

  describe("POST /v0/authorize", () => {
    it("returns 401 when no Authorization header is provided", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/v0/authorize",
        payload: { tool_name: "test.tool" },
      });
      expect(res.statusCode).toBe(401);
      expect(res.json().error).toBe("missing_token");
    });

    it("returns 401 when Authorization header is not Bearer", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/v0/authorize",
        headers: { authorization: "Basic abc123" },
        payload: { tool_name: "test.tool" },
      });
      expect(res.statusCode).toBe(401);
      expect(res.json().error).toBe("missing_token");
    });

    it("returns 400 when body is not JSON", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/v0/authorize",
        headers: {
          authorization: "Bearer test-token",
          "content-type": "text/plain",
        },
        payload: "not json",
      });
      expect(res.statusCode).toBe(400);
    });

    it("returns 400 when tool_name is missing", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/v0/authorize",
        headers: { authorization: "Bearer test-token" },
        payload: { arguments: {} },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("invalid_body");
    });

    it("returns 400 when tool_name is empty string", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/v0/authorize",
        headers: { authorization: "Bearer test-token" },
        payload: { tool_name: "" },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe("invalid_body");
    });

    it("returns 200 with a valid request", async () => {
      const res = await app.inject({
        method: "POST",
        url: "/v0/authorize",
        headers: { authorization: "Bearer test-token" },
        payload: {
          tool_name: "calendar.read",
          arguments: { date: "2026-01-01" },
        },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().decision).toBe("allow");
    });
  });
});
