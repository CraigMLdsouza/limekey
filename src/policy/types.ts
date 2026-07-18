import type { AuthorizationRequest } from "../types/authorization.js";

/**
 * Core types for the Limekey policy engine.
 * These are intentionally minimal in v0.1 — the goal is a stable contract
 * that a Rego/OPA-backed engine (v0.2) can implement identically.
 */

export type Decision = "allow" | "deny" | "step_up";

export interface RuleMatch {
  tool_name?: string;
  agent_id_in?: string[];
  agent_id_not_in?: string[];
  principal_in?: string[];
  arguments?: Record<string, unknown>;
}

export interface Rule {
  name: string;
  match: RuleMatch;
  effect: Decision;
}

export interface PolicyResult {
  decision: Decision;
  matchedRule: string;
}

/**
 * A PolicyEngine turns an AuthorizationRequest into a decision. v0.1 ships a
 * YAML-rule implementation; v0.2 adds a Rego/OPA-backed one behind this same
 * interface so callers never need to change.
 *
 * The engine must never import MCP-specific or HTTP-specific types.
 */
export interface PolicyEngine {
  evaluate(req: AuthorizationRequest): Promise<PolicyResult>;
}
