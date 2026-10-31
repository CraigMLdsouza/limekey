import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as http from "node:http";
import * as jose from "jose";
import {
  TokenValidator,
  TokenValidationError,
  type TokenValidationConfig,
} from "./tokenValidator.js";

/* ------------------------------------------------------------------ */
/*  Shared test infrastructure                                        */
/* ------------------------------------------------------------------ */

let server: http.Server;
let jwksUri: string;
let privateKey: jose.KeyLike;
let publicJwk: jose.JWK;

// A second key pair that the validator does NOT trust.
let untrustedPrivateKey: jose.KeyLike;

const ISSUER = "https://auth.example.com";
const AUDIENCE = "https://mcp.example.com";
const AGENT_ID_CLAIM = "agent_id";

/** Helper – build a default TokenValidationConfig pointing at the local server. */
function makeConfig(overrides: Partial<TokenValidationConfig> = {}): TokenValidationConfig {
  return {
    issuer: ISSUER,
    jwksUri,
    requiredAudience: AUDIENCE,
    agentIdClaim: AGENT_ID_CLAIM,
    ...overrides,
  };
}

/** Helper – mint a signed JWT with sensible defaults. */
async function mintToken(
  overrides: Record<string, unknown> = {},
  signingKey: jose.KeyLike = privateKey,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  const claims: Record<string, unknown> = {
    sub: "user-123",
    aud: AUDIENCE,
    iss: ISSUER,
    iat: now,
    exp: now + 300, // 5 minutes from now
    [AGENT_ID_CLAIM]: "agent-abc",
    ...overrides,
  };

  return new jose.SignJWT(claims as jose.JWTPayload)
    .setProtectedHeader({ alg: "RS256" })
    .sign(signingKey);
}

/* ------------------------------------------------------------------ */
/*  Lifecycle – spin up / tear down the local JWKS server              */
/* ------------------------------------------------------------------ */

beforeAll(async () => {
  // Generate two RSA key pairs – one trusted (served via JWKS), one not.
  const [trusted, untrusted] = await Promise.all([
    jose.generateKeyPair("RS256"),
    jose.generateKeyPair("RS256"),
  ]);
  privateKey = trusted.privateKey;
  untrustedPrivateKey = untrusted.privateKey;

  publicJwk = await jose.exportJWK(trusted.publicKey);

  const jwksJson = JSON.stringify({ keys: [publicJwk] });

  // Create a tiny HTTP server that serves the JWKS document.
  server = http.createServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(jwksJson);
  });

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve());
  });

  const addr = server.address() as { port: number };
  jwksUri = `http://127.0.0.1:${addr.port}/.well-known/jwks.json`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
});

/* ------------------------------------------------------------------ */
/*  Tests                                                              */
/* ------------------------------------------------------------------ */

describe("TokenValidator", () => {
  /* ---------- happy path ---------- */

  it("accepts a valid token with correct issuer, audience, and agent_id", async () => {
    const validator = new TokenValidator(makeConfig());
    const token = await mintToken();

    const result = await validator.validate(token);

    expect(result.principal).toBe("user-123");
    expect(result.agentId).toBe("agent-abc");
    expect(result.raw).toBeDefined();
    expect(result.raw.sub).toBe("user-123");
    expect(result.raw[AGENT_ID_CLAIM]).toBe("agent-abc");
  });

  it("accepts a token whose aud is a single-element array", async () => {
    const validator = new TokenValidator(makeConfig());
    const token = await mintToken({ aud: [AUDIENCE] });

    const result = await validator.validate(token);

    expect(result.principal).toBe("user-123");
    expect(result.agentId).toBe("agent-abc");
  });

  it("accepts a token whose aud is a multi-element array containing the required audience", async () => {
    const validator = new TokenValidator(makeConfig());
    const token = await mintToken({ aud: ["https://other.example.com", AUDIENCE] });

    const result = await validator.validate(token);

    expect(result.agentId).toBe("agent-abc");
  });

  it("accepts a token whose resource claim matches the required audience", async () => {
    const validator = new TokenValidator(makeConfig());
    const token = await mintToken({ aud: "https://other.example.com", resource: AUDIENCE });

    const result = await validator.validate(token);

    expect(result.agentId).toBe("agent-abc");
  });

  it("accepts a token whose resource claim is an array containing the required audience", async () => {
    const validator = new TokenValidator(makeConfig());
    const token = await mintToken({ aud: "https://other.example.com", resource: ["https://another.example.com", AUDIENCE] });

    const result = await validator.validate(token);

    expect(result.agentId).toBe("agent-abc");
  });

  /* ---------- expired tokens ---------- */

  it("rejects an expired token with code 'invalid_signature'", async () => {
    const validator = new TokenValidator(makeConfig());
    const token = await mintToken({
      iat: Math.floor(Date.now() / 1000) - 600,
      exp: Math.floor(Date.now() / 1000) - 300, // expired 5 min ago
    });

    await expect(validator.validate(token)).rejects.toThrow(TokenValidationError);
    await expect(validator.validate(token)).rejects.toMatchObject({
      code: "invalid_signature",
    });
  });

  /* ---------- wrong audience ---------- */

  it("rejects a token with a different audience with code 'wrong_resource'", async () => {
    const validator = new TokenValidator(makeConfig());
    const token = await mintToken({ aud: "https://wrong-server.example.com" });

    await expect(validator.validate(token)).rejects.toThrow(TokenValidationError);
    await expect(validator.validate(token)).rejects.toMatchObject({
      code: "wrong_resource",
    });
  });

  it("rejects a token whose aud array does not include the required audience", async () => {
    const validator = new TokenValidator(makeConfig());
    const token = await mintToken({
      aud: ["https://a.example.com", "https://b.example.com"],
    });

    await expect(validator.validate(token)).rejects.toThrow(TokenValidationError);
    await expect(validator.validate(token)).rejects.toMatchObject({
      code: "wrong_resource",
    });
  });

  /* ---------- missing / empty agent_id ---------- */

  it("rejects a token missing the agent_id claim with code 'missing_agent_id'", async () => {
    const validator = new TokenValidator(makeConfig());

    // Build token without the agent_id claim at all.
    const now = Math.floor(Date.now() / 1000);
    const token = await new jose.SignJWT({
      sub: "user-123",
      aud: AUDIENCE,
      iss: ISSUER,
      iat: now,
      exp: now + 300,
      // note: no agent_id
    } as jose.JWTPayload)
      .setProtectedHeader({ alg: "RS256" })
      .sign(privateKey);

    await expect(validator.validate(token)).rejects.toThrow(TokenValidationError);
    await expect(validator.validate(token)).rejects.toMatchObject({
      code: "missing_agent_id",
    });
  });

  it("rejects a token with an empty string agent_id with code 'missing_agent_id'", async () => {
    const validator = new TokenValidator(makeConfig());
    const token = await mintToken({ [AGENT_ID_CLAIM]: "" });

    await expect(validator.validate(token)).rejects.toThrow(TokenValidationError);
    await expect(validator.validate(token)).rejects.toMatchObject({
      code: "missing_agent_id",
    });
  });

  it("rejects a token with a non-string agent_id with code 'missing_agent_id'", async () => {
    const validator = new TokenValidator(makeConfig());
    const token = await mintToken({ [AGENT_ID_CLAIM]: 42 });

    await expect(validator.validate(token)).rejects.toThrow(TokenValidationError);
    await expect(validator.validate(token)).rejects.toMatchObject({
      code: "missing_agent_id",
    });
  });

  /* ---------- wrong issuer ---------- */

  it("rejects a token with a different issuer with code 'invalid_signature'", async () => {
    const validator = new TokenValidator(makeConfig());
    const token = await mintToken({ iss: "https://evil-issuer.example.com" });

    await expect(validator.validate(token)).rejects.toThrow(TokenValidationError);
    await expect(validator.validate(token)).rejects.toMatchObject({
      code: "invalid_signature",
    });
  });

  /* ---------- wrong signing key ---------- */

  it("rejects a token signed with an untrusted key with code 'invalid_signature'", async () => {
    const validator = new TokenValidator(makeConfig());
    const token = await mintToken({}, untrustedPrivateKey);

    await expect(validator.validate(token)).rejects.toThrow(TokenValidationError);
    await expect(validator.validate(token)).rejects.toMatchObject({
      code: "invalid_signature",
    });
  });

  /* ---------- completely garbage token ---------- */

  it("rejects a non-JWT string with code 'invalid_signature'", async () => {
    const validator = new TokenValidator(makeConfig());

    await expect(validator.validate("not-a-jwt")).rejects.toThrow(TokenValidationError);
    await expect(validator.validate("not-a-jwt")).rejects.toMatchObject({
      code: "invalid_signature",
    });
  });

  /* ---------- custom agentIdClaim ---------- */

  it("reads agent identity from a custom claim name", async () => {
    const customClaim = "custom_agent";
    const validator = new TokenValidator(makeConfig({ agentIdClaim: customClaim }));
    const token = await mintToken({ [customClaim]: "special-agent" });

    const result = await validator.validate(token);

    expect(result.agentId).toBe("special-agent");
  });

  /* ---------- session binding (T0-5) ---------- */

  it("accepts a token bound to a session when the correct session_id is provided", async () => {
    const validator = new TokenValidator(makeConfig());
    const token = await mintToken({ session_id: "sess-123" });

    const result = await validator.validate(token, "sess-123");
    expect(result.agentId).toBe("agent-abc");
  });

  it("rejects a token bound to a session when a different session_id is provided", async () => {
    const validator = new TokenValidator(makeConfig());
    const token = await mintToken({ session_id: "sess-123" });

    await expect(validator.validate(token, "sess-wrong")).rejects.toThrow(TokenValidationError);
    await expect(validator.validate(token, "sess-wrong")).rejects.toMatchObject({
      code: "invalid_signature",
    });
  });

  it("rejects a token bound to a session when no session_id is provided", async () => {
    const validator = new TokenValidator(makeConfig());
    const token = await mintToken({ session_id: "sess-123" });

    await expect(validator.validate(token)).rejects.toThrow(TokenValidationError);
    await expect(validator.validate(token)).rejects.toMatchObject({
      code: "invalid_signature",
    });
  });

  it("accepts an unbound token when no session_id is provided", async () => {
    const validator = new TokenValidator(makeConfig());
    const token = await mintToken(); // unbound

    const result = await validator.validate(token);
    expect(result.agentId).toBe("agent-abc");
  });
});
