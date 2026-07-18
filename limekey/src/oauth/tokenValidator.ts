import { createRemoteJWKSet, jwtVerify } from "jose";

export interface TokenValidationConfig {
  issuer: string;
  jwksUri: string;
  requiredAudience: string; // RFC 8707 resource indicator this server expects
  agentIdClaim: string; // e.g. "agent_id"
}

export interface ValidatedToken {
  principal: string; // `sub` claim
  agentId: string; // value of agentIdClaim
  raw: Record<string, unknown>;
}

export class TokenValidationError extends Error {
  constructor(
    message: string,
    public code:
      | "invalid_signature"
      | "expired"
      | "wrong_resource"
      | "missing_agent_id",
  ) {
    super(message);
  }
}

/**
 * Validates a bearer token against the configured issuer/JWKS, and enforces
 * RFC 8707: the token's audience/resource must match this server's
 * resource identifier, so a token minted for a different MCP server can't
 * be replayed here.
 */
export class TokenValidator {
  private jwks: ReturnType<typeof createRemoteJWKSet>;

  constructor(private config: TokenValidationConfig) {
    this.jwks = createRemoteJWKSet(new URL(config.jwksUri));
  }

  async validate(bearerToken: string): Promise<ValidatedToken> {
    let payload;
    try {
      const result = await jwtVerify(bearerToken, this.jwks, {
        issuer: this.config.issuer,
      });
      payload = result.payload;
    } catch (err) {
      throw new TokenValidationError(
        `token signature/issuer/expiry check failed: ${(err as Error).message}`,
        "invalid_signature",
      );
    }

    const aud = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : [];
    const resource = Array.isArray(payload.resource)
      ? payload.resource
      : payload.resource
        ? [payload.resource]
        : [];
    const targets = [...aud, ...resource];

    if (!targets.includes(this.config.requiredAudience)) {
      throw new TokenValidationError(
        `token resource indicator (aud/resource) does not match this server (${this.config.requiredAudience})`,
        "wrong_resource",
      );
    }

    const agentId = payload[this.config.agentIdClaim];
    if (typeof agentId !== "string" || agentId.length === 0) {
      throw new TokenValidationError(
        `token missing required agent identity claim "${this.config.agentIdClaim}"`,
        "missing_agent_id",
      );
    }

    return {
      principal: String(payload.sub),
      agentId,
      raw: payload as Record<string, unknown>,
    };
  }
}
