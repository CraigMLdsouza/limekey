import { describe, it, expect, afterEach } from "vitest";
import * as http from "node:http";
import * as net from "node:net";
import { UpstreamManager } from "./upstream.js";
import type { UpstreamConfig } from "../config.js";

// ---------------------------------------------------------------------------
// Helpers — mock upstream MCP echo server
// ---------------------------------------------------------------------------

/**
 * Creates a mock upstream MCP process configuration that echoes back a
 * well-formed initialize response then responds to each request with a
 * result containing the received method name.
 *
 * We use a node script passed as inline -e argument so no file I/O is needed.
 */
function makeEchoConfig(extraArgs: string[] = []): UpstreamConfig {
  // Inline node script: handles initialize then echoes all other requests
  const script = `
    const rl = require("readline").createInterface({ input: process.stdin });
    rl.on("line", (line) => {
      try {
        const req = JSON.parse(line);
        if (req.method === "initialize") {
          process.stdout.write(JSON.stringify({
            jsonrpc: "2.0",
            id: req.id,
            result: {
              protocolVersion: "2024-11-05",
              capabilities: {},
              serverInfo: { name: "mock-upstream", version: "0.0.1" }
            }
          }) + "\\n");
        } else if (req.id !== undefined && req.id !== null) {
          process.stdout.write(JSON.stringify({
            jsonrpc: "2.0",
            id: req.id,
            result: { echo: req.method }
          }) + "\\n");
        }
      } catch {}
    });
  `;

  return {
    command: "node",
    args: ["-e", script, ...extraArgs],
    passthrough_env: [],
    startup_timeout: 5,
    request_timeout: 5,
  };
}

/**
 * Creates a mock upstream that delays responses by delayMs before responding.
 */
function makeSlowConfig(delayMs: number): UpstreamConfig {
  const script = `
    const rl = require("readline").createInterface({ input: process.stdin });
    rl.on("line", (line) => {
      try {
        const req = JSON.parse(line);
        if (req.method === "initialize") {
          // Initialize responds immediately
          process.stdout.write(JSON.stringify({
            jsonrpc: "2.0", id: req.id,
            result: { protocolVersion: "2024-11-05", capabilities: {}, serverInfo: { name: "slow", version: "0" } }
          }) + "\\n");
        } else if (req.id !== undefined && req.id !== null) {
          setTimeout(() => {
            process.stdout.write(JSON.stringify({
              jsonrpc: "2.0", id: req.id, result: { slow: true }
            }) + "\\n");
          }, ${delayMs});
        }
      } catch {}
    });
  `;
  return {
    command: "node",
    args: ["-e", script],
    passthrough_env: [],
    startup_timeout: 5,
    request_timeout: 5,
  };
}

/**
 * Creates a mock upstream that never responds to initialize (causes startup timeout).
 */
function makeSilentConfig(): UpstreamConfig {
  return {
    command: "node",
    args: ["-e", "// silent — never writes to stdout"],
    passthrough_env: [],
    startup_timeout: 1, // 1 second so the test is fast
    request_timeout: 5,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("UpstreamManager", () => {
  let manager: UpstreamManager | null = null;

  afterEach(async () => {
    if (manager) {
      await manager.shutdown();
      manager = null;
    }
  });

  it("starts and completes the initialize handshake", async () => {
    manager = new UpstreamManager(makeEchoConfig());
    // Should resolve without throwing
    await expect(manager.start(5000)).resolves.toBeUndefined();
  });

  it("sends a request and receives a response", async () => {
    manager = new UpstreamManager(makeEchoConfig());
    await manager.start(5000);

    const res = await manager.send(
      { jsonrpc: "2.0", id: 1, method: "tools/list" },
      5000,
    );
    expect(res.result).toEqual({ echo: "tools/list" });
  });

  it("handles concurrent requests correctly", async () => {
    manager = new UpstreamManager(makeEchoConfig());
    await manager.start(5000);

    const [r1, r2, r3] = await Promise.all([
      manager.send({ jsonrpc: "2.0", id: 1, method: "tools/list" }, 5000),
      manager.send({ jsonrpc: "2.0", id: 2, method: "tools/call" }, 5000),
      manager.send({ jsonrpc: "2.0", id: 3, method: "resources/list" }, 5000),
    ]);

    expect((r1.result as Record<string, unknown>).echo).toBe("tools/list");
    expect((r2.result as Record<string, unknown>).echo).toBe("tools/call");
    expect((r3.result as Record<string, unknown>).echo).toBe("resources/list");
  });

  it("rejects in-flight requests when startup_timeout fires", async () => {
    manager = new UpstreamManager(makeSilentConfig());
    // The silent upstream exits immediately (code=0) without ever sending an
    // initialize response — we expect start() to reject with any error.
    await expect(manager.start(1000)).rejects.toThrow(/timed out|exited/i);
  });

  it("rejects a request when request_timeout fires", async () => {
    // slow upstream delays 2000ms, but request_timeout is 200ms
    manager = new UpstreamManager({
      ...makeSlowConfig(2000),
      request_timeout: 0.2, // 200ms
    });
    await manager.start(5000);

    await expect(
      manager.send({ jsonrpc: "2.0", id: 1, method: "tools/list" }, 200),
    ).rejects.toThrow(/timed out/i);
  });

  it("emits crash event and rejects in-flight requests when upstream exits", async () => {
    // Script that exits immediately after responding to initialize
    const script = `
      const rl = require("readline").createInterface({ input: process.stdin });
      rl.on("line", (line) => {
        const req = JSON.parse(line);
        if (req.method === "initialize") {
          process.stdout.write(JSON.stringify({
            jsonrpc: "2.0", id: req.id,
            result: { protocolVersion: "2024-11-05", capabilities: {}, serverInfo: { name: "crash", version: "0" } }
          }) + "\\n");
          // Exit after a short delay so the send() below can be in-flight
          setTimeout(() => process.exit(0), 100);
        }
      });
    `;

    manager = new UpstreamManager({
      command: "node",
      args: ["-e", script],
      passthrough_env: [],
      startup_timeout: 5,
      request_timeout: 5,
    });

    await manager.start(5000);

    const crashPromise = new Promise<void>((resolve) => {
      manager!.once("crash", () => resolve());
    });

    // Issue a request that will be in-flight when the upstream exits
    const sendPromise = manager.send(
      { jsonrpc: "2.0", id: 99, method: "tools/list" },
      5000,
    );

    await crashPromise;
    await expect(sendPromise).rejects.toThrow(/exited/i);
  });
});
