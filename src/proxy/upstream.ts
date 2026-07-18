import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { createInterface } from "node:readline";
import type { UpstreamConfig } from "../config.js";
import { RequestIdMap } from "./idmap.js";
import type { JsonRpcRequest, JsonRpcResponse } from "../types/jsonrpc.js";

/**
 * Manages the lifecycle of a single upstream MCP server process.
 *
 * Responsibilities:
 *  - Spawn the process with an allowlisted env subset.
 *  - Complete the MCP initialize handshake before signalling ready.
 *  - Buffer stdout line-by-line and route JSON-RPC responses to callers.
 *  - Enforce per-request timeouts.
 *  - Detect crashes, reject all in-flight requests, and emit "crash".
 *    Does NOT restart — that is the operator's job (process supervisor).
 *
 * Emits:
 *  - "crash" (exitCode: number | null)  when the upstream process exits.
 */
export class UpstreamManager extends EventEmitter {
  private readonly cfg: UpstreamConfig;
  private readonly idMap = new RequestIdMap();
  private proc: ReturnType<typeof spawn> | null = null;
  private crashed = false;

  constructor(cfg: UpstreamConfig) {
    super();
    this.cfg = cfg;
  }

  /**
   * Spawn the upstream and complete the MCP initialize handshake.
   * Resolves when the upstream is ready to accept forwarded requests.
   * Rejects if startup times out or the process crashes during startup.
   *
   * @param startupTimeoutMs  Maximum milliseconds to wait for initialize.
   */
  async start(startupTimeoutMs: number): Promise<void> {
    // Build a filtered env starting with essential system variables.
    const env: Record<string, string> = {};
    const essentialKeys = [
      "PATH",
      "PATHEXT",
      "SystemRoot",
      "windir",
      "HOME",
      "USERPROFILE",
      "APPDATA",
      "TMP",
      "TEMP",
      "TERM",
      "LANG",
      "LC_ALL",
    ];

    for (const key of essentialKeys) {
      const val = process.env[key];
      if (val !== undefined) {
        env[key] = val;
      }
    }

    for (const key of this.cfg.passthrough_env ?? []) {
      const val = process.env[key];
      if (val !== undefined) {
        env[key] = val;
      }
    }

    const debugEnv: Record<string, string> = {};
    for (const [key, val] of Object.entries(env)) {
      if (
        key.includes("TOKEN") ||
        key.includes("KEY") ||
        key.includes("SECRET") ||
        key.includes("PASSWORD")
      ) {
        debugEnv[key] = "[REDACTED]";
      } else {
        debugEnv[key] = val;
      }
    }

    process.stderr.write(
      `[limekey-proxy] Spawning upstream:\n` +
      `COMMAND: ${JSON.stringify(this.cfg.command)}\n` +
      `ARGS: ${JSON.stringify(this.cfg.args ?? [])}\n` +
      `ENV: ${JSON.stringify(debugEnv)}\n`,
    );

    this.proc = spawn(this.cfg.command, this.cfg.args ?? [], {
      env,
      stdio: ["pipe", "pipe", "inherit"],
    });

    if (!this.proc.stdout || !this.proc.stdin) {
      throw new Error("Failed to attach stdio to upstream process");
    }

    // Line-buffer upstream stdout and route JSON-RPC responses.
    const rl = createInterface({ input: this.proc.stdout, crlfDelay: Infinity });
    rl.on("line", (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;

      let msg: JsonRpcResponse;
      try {
        msg = JSON.parse(trimmed) as JsonRpcResponse;
      } catch {
        process.stderr.write(`[limekey-proxy] upstream sent non-JSON line: ${trimmed}\n`);
        return;
      }

      if (msg.id !== null && msg.id !== undefined) {
        this.idMap.resolve(msg.id as number, msg);
      }
      // Notifications (id absent) are not currently forwarded to the client.
      // This is acceptable for v1 — subscriptions and streaming are deferred.
    });

    // On crash: reject all in-flight requests and emit event.
    this.proc.on("exit", (code) => {
      this.crashed = true;
      process.stderr.write(`[limekey-proxy] upstream exited (code=${code ?? "null"})\n`);
      this.idMap.rejectAll(
        new Error(`Upstream process exited unexpectedly (code=${code ?? "null"})`),
      );
      this.emit("crash", code);
    });

    // Complete the initialize handshake within startupTimeoutMs.
    await this.sendInternal(
      {
        jsonrpc: "2.0",
        id: null, // replaced with proxy-generated ID inside sendInternal
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "limekey-proxy", version: "0.1.0" },
        },
      },
      startupTimeoutMs,
    );

    // Send the required initialized notification (no response expected).
    this.proc.stdin.write(
      JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n",
    );
  }

  /**
   * Forward a JSON-RPC request or notification to the upstream.
   *
   * If the message has no ID, it is treated as a notification: forwarded
   * directly to the upstream stdout/stdin without registering request IDs or
   * expecting responses.
   *
   * If the message has an ID, the proxy substitutes a proxy-generated ID,
   * routes the response using RequestIdMap, and awaits the response.
   *
   * @param req              The request or notification to forward.
   * @param requestTimeoutMs Per-request timeout in milliseconds (for requests).
   */
  async send(req: JsonRpcRequest, requestTimeoutMs: number): Promise<JsonRpcResponse | void> {
    if (req.id === undefined || req.id === null) {
      if (!this.proc?.stdin || this.crashed) return;
      const outgoing = {
        jsonrpc: req.jsonrpc,
        method: req.method,
        params: req.params,
      };
      this.proc.stdin.write(JSON.stringify(outgoing) + "\n");
      return;
    }
    return this.sendInternal(req as JsonRpcRequest & { id: number | string }, requestTimeoutMs);
  }

  /**
   * Gracefully shut down the upstream process.
   * Waits up to 5 seconds for the process to exit before force-killing.
   */
  async shutdown(): Promise<void> {
    if (!this.proc || this.crashed) return;

    try {
      // Close stdin — well-behaved MCP servers will exit when stdin closes.
      this.proc.stdin?.end();
    } catch {
      // ignore write errors during shutdown
    }

    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        this.proc?.kill("SIGKILL");
        resolve();
      }, 5000);
      this.proc!.once("exit", () => {
        clearTimeout(timer);
        resolve();
      });
    });
  }

  // ---------------------------------------------------------------------------
  // Private
  // ---------------------------------------------------------------------------

  private sendInternal(req: JsonRpcRequest, timeoutMs: number): Promise<JsonRpcResponse> {
    return new Promise((resolve, reject) => {
      if (!this.proc?.stdin || this.crashed) {
        reject(new Error("Upstream process is not running"));
        return;
      }

      // Register before sending so the response can never arrive before we
      // have an entry in the map.
      let upstreamId!: number;

      const wrappedResolve = (msg: JsonRpcResponse): void => {
        clearTimeout(timer);
        resolve(msg);
      };

      const wrappedReject = (err: Error): void => {
        clearTimeout(timer);
        reject(err);
      };

      upstreamId = this.idMap.register(req.id ?? null, wrappedResolve, wrappedReject);

      const timer = setTimeout(() => {
        this.idMap.reject(
          upstreamId,
          new Error(`Upstream request timed out after ${timeoutMs}ms`),
        );
      }, timeoutMs);

      // Send with the proxy-generated ID, not the client's ID.
      const outgoing: JsonRpcRequest = { ...req, id: upstreamId };
      this.proc.stdin.write(JSON.stringify(outgoing) + "\n");
    });
  }
}
