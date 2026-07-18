import type { JsonRpcResponse } from "../types/jsonrpc.js";

/**
 * Maps proxy-generated upstream request IDs back to client request IDs and
 * pending promise callbacks.
 *
 * The proxy never exposes client-generated IDs to the upstream. It generates
 * its own monotonic IDs for every forwarded request and uses this map to route
 * upstream responses back to the correct client.
 *
 * All methods are synchronous and safe to call concurrently — Node.js single-
 * threaded execution guarantees no interleaving within a single tick.
 */
export class RequestIdMap {
  private readonly pending = new Map<
    number,
    {
      resolve: (msg: JsonRpcResponse) => void;
      reject: (err: Error) => void;
    }
  >();

  private counter = 0;

  /**
   * Register a new pending request.
   *
   * @param _clientId  The original client request ID (kept for future
   *                   correlation logging; not used for routing).
   * @param resolve    Called when the upstream response arrives.
   * @param reject     Called on timeout or upstream crash.
   * @returns          The upstream request ID assigned to this entry.
   */
  register(
    _clientId: string | number | null,
    resolve: (msg: JsonRpcResponse) => void,
    reject: (err: Error) => void,
  ): number {
    const upstreamId = ++this.counter;
    this.pending.set(upstreamId, { resolve, reject });
    return upstreamId;
  }

  /** Route an upstream response to the matching pending request. No-op if not found. */
  resolve(upstreamId: number, msg: JsonRpcResponse): void {
    const entry = this.pending.get(upstreamId);
    if (entry) {
      this.pending.delete(upstreamId);
      entry.resolve(msg);
    }
  }

  /** Reject a specific pending request. No-op if not found. */
  reject(upstreamId: number, err: Error): void {
    const entry = this.pending.get(upstreamId);
    if (entry) {
      this.pending.delete(upstreamId);
      entry.reject(err);
    }
  }

  /** Reject all pending requests — called on upstream process crash. */
  rejectAll(err: Error): void {
    for (const [id, entry] of this.pending) {
      this.pending.delete(id);
      entry.reject(err);
    }
  }

  /** Number of in-flight requests. Useful for drain-before-shutdown. */
  get size(): number {
    return this.pending.size;
  }
}
