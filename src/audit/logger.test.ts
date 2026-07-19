import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, rmSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { FileAuditSink, hashArguments } from "./logger.js";
import type { AuditEvent } from "./types.js";

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function makeTmpDir(): string {
  const dir = join(tmpdir(), `limekey-test-${randomUUID()}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function sampleEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    request_id: "test-req-uuid-1234",
    ts: "2026-07-17T16:00:00.000Z",
    agent_id: "agent-1",
    principal: "user@example.com",
    tool_name: "read_file",
    arguments_hash: "sha256:abc123",
    decision: "allow",
    matched_rule: "rule-1",
    step_up: null,
    latency_ms: 42,
    ...overrides,
  };
}

/* ------------------------------------------------------------------ */
/*  hashArguments()                                                     */
/* ------------------------------------------------------------------ */

describe("hashArguments", () => {
  it("produces a deterministic sha256 hash", () => {
    const args = { file: "secret.csv", mode: "read" };
    const hash1 = hashArguments(args);
    const hash2 = hashArguments(args);
    expect(hash1).toBe(hash2);
  });

  it("produces the same hash regardless of key insertion order", () => {
    const a = { file: "secret.csv", mode: "read" };
    const b = { mode: "read", file: "secret.csv" };
    expect(hashArguments(a)).toBe(hashArguments(b));
  });

  it("produces different hashes for different arguments", () => {
    const hash1 = hashArguments({ file: "a.csv" });
    const hash2 = hashArguments({ file: "b.csv" });
    expect(hash1).not.toBe(hash2);
  });

  it("returns a hash in the format 'sha256:<64 hex chars>'", () => {
    const hash = hashArguments({ key: "value" });
    expect(hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("handles an empty object", () => {
    const hash = hashArguments({});
    expect(hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    // Deterministic for same input
    expect(hash).toBe(hashArguments({}));
  });
});

/* ------------------------------------------------------------------ */
/*  FileAuditSink                                                      */
/* ------------------------------------------------------------------ */

describe("FileAuditSink", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  /* ---- init() ---------------------------------------------------- */

  describe("init()", () => {
    it("creates the output directory if it doesn't exist", async () => {
      const nested = join(tmpDir, "a", "b", "c");
      const filePath = join(nested, "audit.jsonl");
      const sink = new FileAuditSink(filePath);

      expect(existsSync(nested)).toBe(false);
      await sink.init();
      expect(existsSync(nested)).toBe(true);
    });

    it("doesn't fail if the directory already exists", async () => {
      const filePath = join(tmpDir, "audit.jsonl");
      const sink = new FileAuditSink(filePath);

      // tmpDir already exists — init should not throw
      await expect(sink.init()).resolves.toBeUndefined();
    });
  });

  /* ---- write() --------------------------------------------------- */

  describe("write()", () => {
    it("appends a valid JSON line to the file", async () => {
      const filePath = join(tmpDir, "audit.jsonl");
      const sink = new FileAuditSink(filePath);
      await sink.init();

      const event = sampleEvent();
      await sink.write(event);

      const content = readFileSync(filePath, "utf-8").trim();
      const parsed = JSON.parse(content);
      expect(parsed).toEqual(event);
    });

    it("multiple writes produce valid JSONL (one JSON object per line)", async () => {
      const filePath = join(tmpDir, "audit.jsonl");
      const sink = new FileAuditSink(filePath);
      await sink.init();

      const events = [
        sampleEvent({ agent_id: "agent-1", latency_ms: 10 }),
        sampleEvent({ agent_id: "agent-2", latency_ms: 20 }),
        sampleEvent({ agent_id: "agent-3", latency_ms: 30 }),
      ];

      for (const event of events) {
        await sink.write(event);
      }

      const lines = readFileSync(filePath, "utf-8")
        .trim()
        .split("\n");

      expect(lines).toHaveLength(3);

      lines.forEach((line, i) => {
        const parsed = JSON.parse(line);
        expect(parsed).toEqual(events[i]);
      });
    });

    it("written events have correct snake_case field names matching the AuditEvent interface", async () => {
      const filePath = join(tmpDir, "audit.jsonl");
      const sink = new FileAuditSink(filePath);
      await sink.init();

      await sink.write(sampleEvent());

      const content = readFileSync(filePath, "utf-8").trim();
      const parsed = JSON.parse(content);

      const expectedKeys: (keyof AuditEvent)[] = [
        "request_id",
        "ts",
        "agent_id",
        "principal",
        "tool_name",
        "arguments_hash",
        "decision",
        "matched_rule",
        "step_up",
        "latency_ms",
        "prev_hash",
        "hash",
      ];

      for (const key of expectedKeys) {
        expect(parsed).toHaveProperty(key);
      }

      // Ensure no extra keys snuck in
      expect(Object.keys(parsed).sort()).toEqual(expectedKeys.slice().sort());
    });
  });

  /* ---- close() --------------------------------------------------- */

  describe("close()", () => {
    it("can be called without error", async () => {
      const filePath = join(tmpDir, "audit.jsonl");
      const sink = new FileAuditSink(filePath);
      await expect(sink.close()).resolves.toBeUndefined();
    });
  });

  /* ---- verifyAuditChain() ---------------------------------------- */

  describe("verifyAuditChain()", () => {
    it("validates an intact chain successfully", async () => {
      const filePath = join(tmpDir, "audit.jsonl");
      const sink = new FileAuditSink(filePath);
      await sink.init();

      const { verifyAuditChain } = await import("./logger.js");

      await sink.write(sampleEvent({ agent_id: "agent-1" }));
      await sink.write(sampleEvent({ agent_id: "agent-2" }));

      expect(verifyAuditChain(filePath)).toBe(true);
    });

    it("detects tampering when an entry is modified on disk", async () => {
      const filePath = join(tmpDir, "audit.jsonl");
      const sink = new FileAuditSink(filePath);
      await sink.init();

      const { verifyAuditChain } = await import("./logger.js");

      await sink.write(sampleEvent({ agent_id: "agent-1" }));
      await sink.write(sampleEvent({ agent_id: "agent-2" }));

      // Tamper with the file
      const { readFileSync, writeFileSync } = await import("node:fs");
      const lines = readFileSync(filePath, "utf-8").trim().split("\n");
      const obj = JSON.parse(lines[0]);
      obj.agent_id = "agent-malicious-tampered";
      lines[0] = JSON.stringify(obj);
      writeFileSync(filePath, lines.join("\n") + "\n");

      expect(verifyAuditChain(filePath)).toBe(false);
    });
  });
});
