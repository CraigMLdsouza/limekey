import { describe, it, expect } from "vitest";
import { RequestIdMap } from "./idmap.js";
import type { JsonRpcResponse } from "../types/jsonrpc.js";

function makeResponse(id: number, result: unknown): JsonRpcResponse {
  return { jsonrpc: "2.0", id, result };
}

describe("RequestIdMap", () => {
  it("registers and resolves a single request", async () => {
    const map = new RequestIdMap();
    const promise = new Promise<JsonRpcResponse>((resolve, reject) => {
      map.register(1, resolve, reject);
    });

    // Upstream ID is 1 (first registered)
    map.resolve(1, makeResponse(1, { ok: true }));
    const res = await promise;
    expect((res.result as Record<string, unknown>).ok).toBe(true);
  });

  it("assigns monotonically increasing upstream IDs", () => {
    const map = new RequestIdMap();
    const id1 = map.register(1, () => {}, () => {});
    const id2 = map.register(2, () => {}, () => {});
    const id3 = map.register(3, () => {}, () => {});
    expect(id2).toBeGreaterThan(id1);
    expect(id3).toBeGreaterThan(id2);
  });

  it("handles concurrent requests correctly", async () => {
    const map = new RequestIdMap();
    const results: number[] = [];

    const p1 = new Promise<JsonRpcResponse>((res) => map.register(10, res, () => {}));
    const p2 = new Promise<JsonRpcResponse>((res) => map.register(20, res, () => {}));
    const p3 = new Promise<JsonRpcResponse>((res) => map.register(30, res, () => {}));

    // Resolve out-of-order
    map.resolve(3, makeResponse(3, { n: 3 }));
    map.resolve(1, makeResponse(1, { n: 1 }));
    map.resolve(2, makeResponse(2, { n: 2 }));

    const [r1, r2, r3] = await Promise.all([p1, p2, p3]);
    results.push((r1.result as Record<string, unknown>).n as number);
    results.push((r2.result as Record<string, unknown>).n as number);
    results.push((r3.result as Record<string, unknown>).n as number);

    expect(results).toEqual([1, 2, 3]);
  });

  it("rejectAll drains all pending entries", async () => {
    const map = new RequestIdMap();
    const errors: string[] = [];

    const p1 = new Promise<void>((_, rej) =>
      map.register(1, () => {}, (e) => { errors.push(e.message); rej(); }),
    );
    const p2 = new Promise<void>((_, rej) =>
      map.register(2, () => {}, (e) => { errors.push(e.message); rej(); }),
    );

    expect(map.size).toBe(2);
    map.rejectAll(new Error("upstream crashed"));
    expect(map.size).toBe(0);

    await Promise.allSettled([p1, p2]);
    expect(errors).toHaveLength(2);
    expect(errors.every((e) => e === "upstream crashed")).toBe(true);
  });

  it("resolve is a no-op for unknown upstream IDs", () => {
    const map = new RequestIdMap();
    // Should not throw
    expect(() => map.resolve(9999, makeResponse(9999, {}))).not.toThrow();
  });

  it("reject is a no-op for unknown upstream IDs", () => {
    const map = new RequestIdMap();
    expect(() => map.reject(9999, new Error("oops"))).not.toThrow();
  });

  it("cleans up the map after resolve", () => {
    const map = new RequestIdMap();
    map.register(1, () => {}, () => {});
    expect(map.size).toBe(1);
    map.resolve(1, makeResponse(1, {}));
    expect(map.size).toBe(0);
  });

  it("cleans up the map after reject", () => {
    const map = new RequestIdMap();
    map.register(1, () => {}, () => {});
    expect(map.size).toBe(1);
    map.reject(1, new Error("timeout"));
    expect(map.size).toBe(0);
  });
});
