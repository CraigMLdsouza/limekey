import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import { appendFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { AuditEvent, AuditSink } from "./types.js";

/**
 * Appends one JSON line per audit event. Swap this out for an HTTP/S3/Kafka
 * sink in v0.2 by implementing AuditSink — callers never need to change.
 */
export class FileAuditSink implements AuditSink {
  constructor(private path: string) {}

  /** Ensure the output directory exists before any writes. */
  async init(): Promise<void> {
    mkdirSync(dirname(this.path), { recursive: true });
  }

  async write(event: AuditEvent): Promise<void> {
    await appendFile(this.path, JSON.stringify(event) + "\n", "utf-8");
  }

  /** No-op for file sink — OS handles flush on close. */
  async close(): Promise<void> {}
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
