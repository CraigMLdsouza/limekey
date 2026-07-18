/**
 * Auth0 adapter.
 *
 * Auth0 supports agent token customization via Actions, which is where an
 * `agent_id` custom claim should be injected before the token reaches
 * Limekey. Configure:
 *
 *   identity.issuer:    https://<your-tenant>.auth0.com/
 *   identity.jwks_uri:  https://<your-tenant>.auth0.com/.well-known/jwks.json
 *   identity.agent_id_claim: "https://limekey.dev/agent_id"  (namespaced,
 *     per Auth0's custom-claim requirements — unnamespaced custom claims
 *     are rejected by Auth0's token pipeline)
 *
 * No other special handling needed — Auth0 issues standard OAuth 2.1 /
 * OIDC tokens that TokenValidator consumes directly.
 */

import {
  TokenValidator,
  type TokenValidationConfig,
} from "../oauth/tokenValidator.js";
import type { LimekeyConfig } from "../config.js";

/**
 * Creates a TokenValidator tuned for Auth0.
 *
 * - Derives jwks_uri from the issuer URL if not explicitly set.
 * - Warns (at config time, not per-request) if the agent_id_claim looks
 *   unnamespaced, since Auth0 silently drops non-namespaced custom claims.
 */
export function createAuth0Validator(config: LimekeyConfig): TokenValidator {
  const identity = config.identity;

  // Auth0 convention: JWKS lives at issuer + .well-known/jwks.json
  const jwksUri =
    identity.jwks_uri ||
    new URL(".well-known/jwks.json", identity.issuer).toString();

  // Auth0 requires custom claims to be namespaced (URL-prefixed).
  // Warn if the configured claim name looks like a bare word.
  if (
    identity.agent_id_claim &&
    !identity.agent_id_claim.includes("/") &&
    !identity.agent_id_claim.includes(":")
  ) {
    console.warn(
      `[limekey:auth0] agent_id_claim "${identity.agent_id_claim}" is not ` +
        `namespaced. Auth0 silently drops unnamespaced custom claims. ` +
        `Consider using a namespaced claim like "https://limekey.dev/agent_id".`,
    );
  }

  const opts: TokenValidationConfig = {
    issuer: identity.issuer,
    jwksUri,
    requiredAudience: identity.required_audience,
    agentIdClaim: identity.agent_id_claim,
  };
  return new TokenValidator(opts);
}
