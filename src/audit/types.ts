import type { Decision } from "../policy/types.js";

/**
 * Audit event schema — field names match the spec (§8) exactly so
 * JSON.stringify produces spec-compliant JSONL without a mapping layer.
 */
export interface AuditEvent {
  /** UUID from AuthorizationRequest — correlates this event with client traces. */
  request_id: string;
  ts: string;
  agent_id: string;
  principal: string;
  tool_name: string;
  arguments_hash: string;
  decision: Decision | "upstream_failure";
  matched_rule: string | null;
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
