import { describe, it, expect, afterEach } from "vitest";
import { createServer, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import { WebhookStepUpProvider, type StepUpRequest } from "./webhook.js";

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

/** Spin up a one-shot HTTP server that calls `handler` for every request. */
function startServer(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<{ server: Server; url: string }> {
  return new Promise((resolve) => {
    const server = createServer(handler);
    // Listen on 0 to get an OS-assigned ephemeral port.
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") throw new Error("unexpected address");
      resolve({ server, url: `http://127.0.0.1:${addr.port}` });
    });
  });
}

/** Gracefully close a server, resolving once all connections are torn down. */
function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

/* ------------------------------------------------------------------ */
/*  Shared fixtures                                                    */
/* ------------------------------------------------------------------ */

const sampleRequest: StepUpRequest = {
  agentId: "agent-42",
  principal: "user@example.com",
  toolName: "delete_database",
  argumentsSummary: '{"target":"production"}',
};

/* ------------------------------------------------------------------ */
/*  Tests                                                              */
/* ------------------------------------------------------------------ */

describe("WebhookStepUpProvider", () => {
  /** Collect servers so afterEach can tear them down even if a test throws. */
  const servers: Server[] = [];

  afterEach(async () => {
    await Promise.all(
      servers.map((s) => closeServer(s).catch(() => {/* already closed */})),
    );
    servers.length = 0;
  });

  // ---- 1. Approved outcome -------------------------------------------

  it("returns 'approved' when webhook responds with {outcome: 'approved'}", async () => {
    const { server, url } = await startServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ outcome: "approved" }));
    });
    servers.push(server);

    const provider = new WebhookStepUpProvider(url, 5);
    const result = await provider.requestApproval(sampleRequest);

    expect(result).toBe("approved");
  });

  // ---- 2. Denied outcome ---------------------------------------------

  it("returns 'denied' when webhook responds with {outcome: 'denied'}", async () => {
    const { server, url } = await startServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ outcome: "denied" }));
    });
    servers.push(server);

    const provider = new WebhookStepUpProvider(url, 5);
    const result = await provider.requestApproval(sampleRequest);

    expect(result).toBe("denied");
  });

  // ---- 3. Unknown outcome → denied -----------------------------------

  it("returns 'denied' when webhook responds with an unrecognised outcome", async () => {
    const { server, url } = await startServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ outcome: "maybe" }));
    });
    servers.push(server);

    const provider = new WebhookStepUpProvider(url, 5);
    const result = await provider.requestApproval(sampleRequest);

    expect(result).toBe("denied");
  });

  // ---- 4. Timeout → 'timeout' (default on_timeout = deny) -----------

  it("returns 'timeout' when the webhook takes longer than timeoutSeconds", async () => {
    const { server, url } = await startServer((_req, res) => {
      // Respond after 2 seconds – well beyond the 0.1 s timeout.
      setTimeout(() => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ outcome: "approved" }));
      }, 2_000);
    });
    servers.push(server);

    const provider = new WebhookStepUpProvider(url, 0.1); // 100 ms
    const result = await provider.requestApproval(sampleRequest);

    expect(result).toBe("timeout");
  });

  // ---- 5. Timeout with on_timeout = 'allow' → 'approved' ------------

  it("returns 'approved' on timeout when on_timeout is 'allow'", async () => {
    const { server, url } = await startServer((_req, res) => {
      setTimeout(() => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ outcome: "denied" }));
      }, 2_000);
    });
    servers.push(server);

    const provider = new WebhookStepUpProvider(url, 0.1, "allow");
    const result = await provider.requestApproval(sampleRequest);

    expect(result).toBe("approved");
  });

  // ---- 6. Verify the JSON body sent to the webhook -------------------

  it("sends the correct JSON body to the webhook", async () => {
    let receivedBody: StepUpRequest | undefined;

    const { server, url } = await startServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        receivedBody = JSON.parse(Buffer.concat(chunks).toString("utf-8")) as StepUpRequest;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ outcome: "approved" }));
      });
    });
    servers.push(server);

    const provider = new WebhookStepUpProvider(url, 5);
    await provider.requestApproval(sampleRequest);

    expect(receivedBody).toEqual({
      agentId: "agent-42",
      principal: "user@example.com",
      toolName: "delete_database",
      argumentsSummary: '{"target":"production"}',
    });
  });

  // ---- 7. Unreachable URL → 'timeout' --------------------------------

  it("returns 'timeout' when the webhook URL is unreachable", async () => {
    // Port 1 is almost certainly not listening and will refuse the connection.
    const provider = new WebhookStepUpProvider("http://127.0.0.1:1/webhook", 2);
    const result = await provider.requestApproval(sampleRequest);

    expect(result).toBe("timeout");
  });
});
