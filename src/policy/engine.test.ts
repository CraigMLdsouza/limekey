import { describe, it, expect, afterEach } from "vitest";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import yaml from "js-yaml";
import { YamlPolicyEngine } from "./engine.js";
import type { ToolCall, Rule } from "./types.js";

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

/** Build a minimal ToolCall with sensible defaults. */
function makeCall(overrides: Partial<ToolCall> = {}): ToolCall {
  return {
    agentId: "agent-1",
    principal: "user@example.com",
    resource: "res://default",
    toolName: "read_file",
    arguments: {},
    context: { ts: new Date().toISOString() },
    ...overrides,
  };
}

/** Write a YAML policy file containing the given rules and return the path. */
function writePolicyFile(dir: string, rules: Rule[]): string {
  const filePath = join(dir, "policy.yaml");
  writeFileSync(filePath, yaml.dump({ rules }), "utf-8");
  return filePath;
}

/* ------------------------------------------------------------------ */
/*  Tests                                                             */
/* ------------------------------------------------------------------ */

describe("YamlPolicyEngine", () => {
  let tempDir: string;

  /** Create a fresh temp directory before each test. */
  function freshDir(): string {
    tempDir = join(tmpdir(), `limekey-test-${randomUUID()}`);
    mkdirSync(tempDir, { recursive: true });
    return tempDir;
  }

  afterEach(() => {
    if (tempDir) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  /* ---- 1. First-match-wins ---- */

  it("uses the first matching rule when multiple rules match", async () => {
    const dir = freshDir();
    const path = writePolicyFile(dir, [
      { name: "first-allow", match: {}, effect: "allow" },
      { name: "second-deny", match: {}, effect: "deny" },
    ]);

    const engine = new YamlPolicyEngine(path);
    const result = await engine.evaluate(makeCall());

    expect(result.decision).toBe("allow");
    expect(result.matchedRule).toBe("first-allow");
  });

  /* ---- 2. tool_name — positive match ---- */

  it("matches a call with the correct tool_name", async () => {
    const dir = freshDir();
    const path = writePolicyFile(dir, [
      { name: "allow-read", match: { tool_name: "read_file" }, effect: "allow" },
    ]);

    const engine = new YamlPolicyEngine(path);
    const result = await engine.evaluate(makeCall({ toolName: "read_file" }));

    expect(result.decision).toBe("allow");
    expect(result.matchedRule).toBe("allow-read");
  });

  /* ---- 3. tool_name — negative match ---- */

  it("does NOT match when tool_name differs", async () => {
    const dir = freshDir();
    const path = writePolicyFile(dir, [
      { name: "allow-read", match: { tool_name: "read_file" }, effect: "allow" },
    ]);

    const engine = new YamlPolicyEngine(path);
    const result = await engine.evaluate(makeCall({ toolName: "delete_file" }));

    expect(result.decision).toBe("deny");
    expect(result.matchedRule).toBe("default");
  });

  /* ---- 4. agent_id_in — positive match ---- */

  it("matches when agentId is in the agent_id_in list", async () => {
    const dir = freshDir();
    const path = writePolicyFile(dir, [
      {
        name: "trusted-agents",
        match: { agent_id_in: ["agent-1", "agent-2"] },
        effect: "allow",
      },
    ]);

    const engine = new YamlPolicyEngine(path);
    const result = await engine.evaluate(makeCall({ agentId: "agent-2" }));

    expect(result.decision).toBe("allow");
    expect(result.matchedRule).toBe("trusted-agents");
  });

  /* ---- 5. agent_id_in — negative match ---- */

  it("does NOT match when agentId is not in the agent_id_in list", async () => {
    const dir = freshDir();
    const path = writePolicyFile(dir, [
      {
        name: "trusted-agents",
        match: { agent_id_in: ["agent-1", "agent-2"] },
        effect: "allow",
      },
    ]);

    const engine = new YamlPolicyEngine(path);
    const result = await engine.evaluate(makeCall({ agentId: "agent-unknown" }));

    expect(result.decision).toBe("deny");
    expect(result.matchedRule).toBe("default");
  });

  /* ---- 6. agent_id_not_in — denies when agentId IS in the exclusion list ---- */

  it("does NOT match when agentId IS in the agent_id_not_in list", async () => {
    const dir = freshDir();
    const path = writePolicyFile(dir, [
      {
        name: "not-blocked",
        match: { agent_id_not_in: ["bad-agent"] },
        effect: "allow",
      },
    ]);

    const engine = new YamlPolicyEngine(path);
    const result = await engine.evaluate(makeCall({ agentId: "bad-agent" }));

    // The rule should NOT match because the agent is in the exclusion list,
    // so we fall through to default deny.
    expect(result.decision).toBe("deny");
    expect(result.matchedRule).toBe("default");
  });

  /* ---- 7. agent_id_not_in — allows when agentId is NOT in the exclusion list ---- */

  it("matches when agentId is NOT in the agent_id_not_in list", async () => {
    const dir = freshDir();
    const path = writePolicyFile(dir, [
      {
        name: "not-blocked",
        match: { agent_id_not_in: ["bad-agent"] },
        effect: "allow",
      },
    ]);

    const engine = new YamlPolicyEngine(path);
    const result = await engine.evaluate(makeCall({ agentId: "good-agent" }));

    expect(result.decision).toBe("allow");
    expect(result.matchedRule).toBe("not-blocked");
  });

  /* ---- 8. principal_in — positive match ---- */

  it("matches when principal is in the principal_in list", async () => {
    const dir = freshDir();
    const path = writePolicyFile(dir, [
      {
        name: "known-users",
        match: { principal_in: ["alice@example.com", "bob@example.com"] },
        effect: "allow",
      },
    ]);

    const engine = new YamlPolicyEngine(path);
    const result = await engine.evaluate(
      makeCall({ principal: "bob@example.com" }),
    );

    expect(result.decision).toBe("allow");
    expect(result.matchedRule).toBe("known-users");
  });

  /* ---- 9. principal_in — negative match ---- */

  it("does NOT match when principal is not in the principal_in list", async () => {
    const dir = freshDir();
    const path = writePolicyFile(dir, [
      {
        name: "known-users",
        match: { principal_in: ["alice@example.com", "bob@example.com"] },
        effect: "allow",
      },
    ]);

    const engine = new YamlPolicyEngine(path);
    const result = await engine.evaluate(
      makeCall({ principal: "eve@example.com" }),
    );

    expect(result.decision).toBe("deny");
    expect(result.matchedRule).toBe("default");
  });

  /* ---- 10. Empty match (catch-all) ---- */

  it("matches everything when the match object is empty (catch-all)", async () => {
    const dir = freshDir();
    const path = writePolicyFile(dir, [
      { name: "catch-all", match: {}, effect: "allow" },
    ]);

    const engine = new YamlPolicyEngine(path);

    // Should match regardless of what the call looks like.
    const result = await engine.evaluate(
      makeCall({
        agentId: "any-agent",
        principal: "anyone@anywhere.com",
        toolName: "anything",
      }),
    );

    expect(result.decision).toBe("allow");
    expect(result.matchedRule).toBe("catch-all");
  });

  /* ---- 11. Default deny ---- */

  it("returns deny with matchedRule 'default' when no rules match", async () => {
    const dir = freshDir();
    const path = writePolicyFile(dir, [
      {
        name: "only-read",
        match: { tool_name: "read_file" },
        effect: "allow",
      },
    ]);

    const engine = new YamlPolicyEngine(path);
    const result = await engine.evaluate(makeCall({ toolName: "write_file" }));

    expect(result.decision).toBe("deny");
    expect(result.matchedRule).toBe("default");
  });

  /* ---- 12. Combined matchers: tool_name + agent_id_not_in ---- */

  it("combines tool_name and agent_id_not_in correctly", async () => {
    const dir = freshDir();
    const path = writePolicyFile(dir, [
      {
        name: "safe-read",
        match: { tool_name: "read_file", agent_id_not_in: ["rogue-agent"] },
        effect: "allow",
      },
    ]);

    const engine = new YamlPolicyEngine(path);

    // Correct tool + non-excluded agent → allow
    const allowed = await engine.evaluate(
      makeCall({ toolName: "read_file", agentId: "good-agent" }),
    );
    expect(allowed.decision).toBe("allow");
    expect(allowed.matchedRule).toBe("safe-read");

    // Correct tool BUT excluded agent → deny (rule doesn't match)
    const blockedAgent = await engine.evaluate(
      makeCall({ toolName: "read_file", agentId: "rogue-agent" }),
    );
    expect(blockedAgent.decision).toBe("deny");
    expect(blockedAgent.matchedRule).toBe("default");

    // Wrong tool + non-excluded agent → deny (tool_name mismatch)
    const wrongTool = await engine.evaluate(
      makeCall({ toolName: "delete_file", agentId: "good-agent" }),
    );
    expect(wrongTool.decision).toBe("deny");
    expect(wrongTool.matchedRule).toBe("default");
  });

  /* ---- 13. step_up effect ---- */

  it("returns step_up decision when the matched rule has step_up effect", async () => {
    const dir = freshDir();
    const path = writePolicyFile(dir, [
      {
        name: "require-mfa",
        match: { tool_name: "transfer_funds" },
        effect: "step_up",
      },
    ]);

    const engine = new YamlPolicyEngine(path);
    const result = await engine.evaluate(
      makeCall({ toolName: "transfer_funds" }),
    );

    expect(result.decision).toBe("step_up");
    expect(result.matchedRule).toBe("require-mfa");
  });
});
