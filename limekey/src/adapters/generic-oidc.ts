/**
 * Generic OIDC adapter.
 *
 * For a standards-compliant OIDC provider, TokenValidator (see
 * ../oauth/tokenValidator.ts) works as-is: issuer + JWKS URI + audience
 * check covers it. This file exists as the extension point for
 * provider-specific quirks (custom claim namespaces, non-standard JWKS
 * rotation behavior, etc.) that don't fit the generic path.
 *
 * v0.1: no overrides needed for a spec-compliant provider.
 */

import {
  TokenValidator,
  type TokenValidationConfig,
} from "../oauth/tokenValidator.js";
import type { LimekeyConfig } from "../config.js";

export function createGenericOidcValidator(
  config: LimekeyConfig,
): TokenValidator {
  const opts: TokenValidationConfig = {
    issuer: config.identity.issuer,
    jwksUri: config.identity.jwks_uri,
    requiredAudience: config.identity.required_audience,
    agentIdClaim: config.identity.agent_id_claim,
  };
  return new TokenValidator(opts);
}
