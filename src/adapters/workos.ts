/**
 * WorkOS adapter.
 *
 * WorkOS acts as an MCP-compatible OAuth 2.1 authorization server directly,
 * including support for the 2026-07-28 MCP spec's resource-server
 * requirements (RFC 9728 / RFC 8707). Configure:
 *
 *   identity.issuer:    your WorkOS AuthKit issuer URL
 *   identity.jwks_uri:  your WorkOS AuthKit JWKS URL
 *   identity.required_audience: the resource identifier you registered
 *     for this MCP server in WorkOS
 *
 * Ensure the agent identity is included as a distinct claim on tokens
 * WorkOS issues to your agent clients (not just the human principal's
 * `sub`) — configure this in your WorkOS AuthKit token customization.
 */

import {
  TokenValidator,
  type TokenValidationConfig,
} from "../oauth/tokenValidator.js";
import type { LimekeyConfig } from "../config.js";

/**
 * Creates a TokenValidator tuned for WorkOS AuthKit.
 *
 * - Derives jwks_uri from the issuer if not explicitly provided.
 */
export function createWorkosValidator(config: LimekeyConfig): TokenValidator {
  const identity = config.identity;

  // WorkOS AuthKit JWKS endpoint follows OIDC convention.
  const jwksUri =
    identity.jwks_uri ||
    new URL(".well-known/jwks.json", identity.issuer).toString();

  const opts: TokenValidationConfig = {
    issuer: identity.issuer,
    jwksUri,
    requiredAudience: identity.required_audience,
    agentIdClaim: identity.agent_id_claim,
  };
  return new TokenValidator(opts);
}
