import { readFileSync } from "node:fs";
import yaml from "js-yaml";
import type { PolicyEngine, PolicyResult, Rule, ToolCall } from "./types.js";

interface RuleFile {
  rules: Rule[];
}

/**
 * Simple first-match-wins YAML policy engine. Deny-by-default: if no rule
 * matches, the call is denied and "matchedRule" is reported as "default".
 */
export class YamlPolicyEngine implements PolicyEngine {
  private rules: Rule[];

  constructor(policyFilePath: string) {
    const raw = readFileSync(policyFilePath, "utf-8");
    const parsed = yaml.load(raw) as RuleFile;
    this.rules = parsed.rules ?? [];
  }

  async evaluate(call: ToolCall): Promise<PolicyResult> {
    for (const rule of this.rules) {
      if (this.matches(rule, call)) {
        return { decision: rule.effect, matchedRule: rule.name };
      }
    }
    return { decision: "deny", matchedRule: "default" };
  }

  private matches(rule: Rule, call: ToolCall): boolean {
    const m = rule.match;

    if (m.tool_name !== undefined && m.tool_name !== call.toolName) {
      return false;
    }
    if (m.agent_id_in && !m.agent_id_in.includes(call.agentId)) {
      return false;
    }
    if (m.agent_id_not_in && m.agent_id_not_in.includes(call.agentId)) {
      return false;
    }
    if (m.principal_in && !m.principal_in.includes(call.principal)) {
      return false;
    }
    if (m.arguments) {
      for (const [key, val] of Object.entries(m.arguments)) {
        if (call.arguments?.[key] !== val) {
          return false;
        }
      }
    }
    // An empty match object (`match: {}`) matches everything — used for
    // the default/catch-all rule.
    return true;
  }
}
