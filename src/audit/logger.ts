import { createHash } from "node:crypto";
import { mkdirSync, existsSync, readFileSync } from "node:fs";
import { open } from "node:fs/promises";
import { dirname } from "node:path";
import type { AuditEvent, AuditSink } from "./types.js";

/**
 * Appends one JSON line per audit event with cryptographic hash-chaining and
 * guaranteed fsync durability.
 */
export class FileAuditSink implements AuditSink {
  private lastHash: string = "0";

  constructor(private path: string) {}

  /** Ensure the output directory exists and recover the last hash from disk. */
  async init(): Promise<void> {
    mkdirSync(dirname(this.path), { recursive: true });

    if (existsSync(this.path)) {
      try {
        const content = readFileSync(this.path, "utf-8").trim();
        if (content) {
          const lines = content.split("\n");
          const lastLine = lines[lines.length - 1].trim();
          if (lastLine) {
            const parsed = JSON.parse(lastLine);
            if (parsed && typeof parsed.hash === "string") {
              this.lastHash = parsed.hash;
            }
          }
        }
      } catch (err) {
        // Safe fallback if the file is unparseable or corrupted
        this.lastHash = "0";
      }
    }
  }

  async write(event: AuditEvent): Promise<void> {
    // 1. Calculate cryptographically chained hashes
    const prevHash = this.lastHash;

    // We compute the hash of the event contents coupled with the prev_hash
    const contentToHash = {
      request_id: event.request_id,
      ts: event.ts,
      agent_id: event.agent_id,
      principal: event.principal,
      tool_name: event.tool_name,
      arguments_hash: event.arguments_hash,
      decision: event.decision,
      matched_rule: event.matched_rule,
      step_up: event.step_up,
      latency_ms: event.latency_ms,
      prev_hash: prevHash,
    };

    const sortedJson = JSON.stringify(contentToHash, Object.keys(contentToHash).sort());
    const currentHash = createHash("sha256").update(sortedJson).digest("hex");

    event.prev_hash = prevHash;
    event.hash = currentHash;
    this.lastHash = currentHash;

    // 2. Open file, write line, and run fsync (durability check)
    const handle = await open(this.path, "a");
    try {
      const line = JSON.stringify(event) + "\n";
      await handle.write(line, null, "utf-8");
      await handle.sync();
    } finally {
      await handle.close();
    }
  }

  /** No-op for file sink. */
  async close(): Promise<void> {}
}

/**
 * Verifies that the audit log hash chain at the given path is intact and untampered.
 * Returns true if valid, false if tampering is detected.
 */
export function verifyAuditChain(path: string): boolean {
  if (!existsSync(path)) return true;
  try {
    const content = readFileSync(path, "utf-8").trim();
    if (!content) return true;

    const lines = content.split("\n");
    let expectedPrevHash = "0";

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      const event = JSON.parse(trimmed);
      if (event.prev_hash !== expectedPrevHash) {
        return false;
      }

      const contentToHash = {
        request_id: event.request_id,
        ts: event.ts,
        agent_id: event.agent_id,
        principal: event.principal,
        tool_name: event.tool_name,
        arguments_hash: event.arguments_hash,
        decision: event.decision,
        matched_rule: event.matched_rule,
        step_up: event.step_up,
        latency_ms: event.latency_ms,
        prev_hash: event.prev_hash,
      };

      const sortedJson = JSON.stringify(contentToHash, Object.keys(contentToHash).sort());
      const currentHash = createHash("sha256").update(sortedJson).digest("hex");

      if (event.hash !== currentHash) {
        return false;
      }

      expectedPrevHash = currentHash;
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * Arguments are hashed rather than stored raw by default, so audit storage
 * doesn't become a second place PII can leak from. Policies can opt in to
 * raw argument logging per-rule in a later version.
 */
export function hashArguments(args: Record<string, unknown>): string {
  const json = JSON.stringify(args, Object.keys(args).sort());
  return "sha256:" + createHash("sha256").update(json).digest("hex");
}
