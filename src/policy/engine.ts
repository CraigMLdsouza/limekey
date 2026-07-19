import { readFileSync } from "node:fs";
import yaml from "js-yaml";
import type { PolicyEngine, PolicyResult, Rule, RuleMatch } from "./types.js";
import type { AuthorizationRequest } from "../types/authorization.js";

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

  async evaluate(req: AuthorizationRequest): Promise<PolicyResult> {
    for (const rule of this.rules) {
      if (this.matches(rule, req)) {
        return { decision: rule.effect, matchedRule: rule.name };
      }
    }
    return { decision: "deny", matchedRule: "default" };
  }

  private matches(rule: Rule, req: AuthorizationRequest): boolean {
    const m: RuleMatch = rule.match;

    if (m.tool_name !== undefined && !this.toolMatches(m.tool_name, req.tool)) {
      return false;
    }
    if (m.agent_id_in && !m.agent_id_in.includes(req.principal.agentId)) {
      return false;
    }
    if (m.agent_id_not_in && m.agent_id_not_in.includes(req.principal.agentId)) {
      return false;
    }
    if (m.principal_in && !m.principal_in.includes(req.principal.sub)) {
      return false;
    }
    if (m.arguments) {
      for (const [key, val] of Object.entries(m.arguments)) {
        if (req.arguments?.[key] !== val) {
          return false;
        }
      }
    }
    // An empty match object (`match: {}`) matches everything — used for
    // the default/catch-all rule.
    return true;
  }

  private toolMatches(pattern: string, tool: string): boolean {
    if (pattern === tool) {
      return true;
    }
    // Regex matching: e.g. "/^ledger\..*/"
    if (pattern.startsWith("/") && pattern.endsWith("/")) {
      try {
        const regexStr = pattern.slice(1, -1);
        const regex = new RegExp(regexStr);
        return regex.test(tool);
      } catch {
        return false;
      }
    }
    // Wildcard matching: e.g. "calendar.*"
    if (pattern.includes("*")) {
      try {
        const regexStr = "^" + pattern
          .replace(/[-\/\\^$+?.()|[\]{}]/g, '\\$&') // escape special characters
          .replace(/\*/g, ".*") + "$";
        const regex = new RegExp(regexStr);
        return regex.test(tool);
      } catch {
        return false;
      }
    }
    return false;
  }
}
