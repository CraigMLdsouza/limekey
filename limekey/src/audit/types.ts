import type { Decision } from "../policy/types.js";

/**
 * Audit event schema — field names match the spec (§8) exactly so
 * JSON.stringify produces spec-compliant JSONL without a mapping layer.
 */
export interface AuditEvent {
  ts: string;
  agent_id: string;
  principal: string;
  resource: string;
  tool_name: string;
  arguments_hash: string;
  decision: Decision;
  matched_rule: string;
  step_up: { requested: boolean; approved?: boolean } | null;
  latency_ms: number;
}

export interface AuditSink {
  /** Ensure output target is ready (e.g. create directories). */
  init?(): Promise<void>;
  /** Write a single audit event. */
  write(event: AuditEvent): Promise<void>;
  /** Flush and close — called on graceful shutdown. */
  close?(): Promise<void>;
}
