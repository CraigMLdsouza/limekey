/**
 * Core types for the Limekey policy engine.
 * These are intentionally minimal in v0.1 — the goal is a stable contract
 * that a Rego/OPA-backed engine (v0.2) can implement identically.
 */

export type Decision = "allow" | "deny" | "step_up";

export interface ToolCall {
  agentId: string;
  principal: string;
  resource: string;
  toolName: string;
  arguments: Record<string, unknown>;
  context: {
    ts: string;
    sessionId?: string;
  };
}

export interface RuleMatch {
  tool_name?: string;
  agent_id_in?: string[];
  agent_id_not_in?: string[];
  principal_in?: string[];
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
 * A PolicyEngine turns a ToolCall into a decision. v0.1 ships a YAML-rule
 * implementation; v0.2 adds a Rego/OPA-backed one behind this same
 * interface so callers never need to change.
 */
export interface PolicyEngine {
  evaluate(call: ToolCall): Promise<PolicyResult>;
}
