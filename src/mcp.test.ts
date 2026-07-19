import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { writeFileSync, unlinkSync, mkdirSync, rmSync } from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as crypto from "node:crypto";
import * as jose from "jose";

const PORT_JWKS = 9100;
const TEMP_DIR = `${os.tmpdir()}/limekey-mcp-test-${crypto.randomUUID()}`;
const CONFIG_PATH = `${TEMP_DIR}/limekey.config.yaml`;
const POLICY_PATH = `${TEMP_DIR}/policies/example.yaml`;
const AUDIT_PATH = `${TEMP_DIR}/audit/log.jsonl`;

let jwksServer: http.Server;
let privateKey: jose.KeyLike;
let publicJwk: jose.JWK;
let token: string;

beforeAll(async () => {
  mkdirSync(TEMP_DIR, { recursive: true });
  mkdirSync(`${TEMP_DIR}/policies`, { recursive: true });
  mkdirSync(`${TEMP_DIR}/audit`, { recursive: true });

  // Generate trusted keys
  const { publicKey, privateKey: privKey } = await jose.generateKeyPair("RS256");
  privateKey = privKey;
  publicJwk = await jose.exportJWK(publicKey);
  const jwksJson = JSON.stringify({ keys: [publicJwk] });

  // Start mock JWKS
  jwksServer = http.createServer((req, res) => {
    if (req.url === "/.well-known/jwks.json") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(jwksJson);
    } else {
      res.writeHead(404).end();
    }
  });

  await new Promise<void>((resolve) => {
    jwksServer.listen(PORT_JWKS, "127.0.0.1", () => resolve());
  });

  // Write temporary config & policies
  const configYaml = `
server:
  listen: 127.0.0.1:8443
  resource_id: "https://mcp.test.internal"

identity:
  provider: generic_oidc
  issuer: "http://127.0.0.1:${PORT_JWKS}"
  jwks_uri: "http://127.0.0.1:${PORT_JWKS}/.well-known/jwks.json"
  agent_id_claim: "agent_id"
  required_audience: "https://mcp.test.internal"

policy:
  engine: yaml
  source: ${POLICY_PATH}
  default: deny

step_up:
  mode: webhook
  webhook_url: "http://127.0.0.1:9005/approve"
  timeout_seconds: 5
  on_timeout: deny

audit:
  sink: file
  path: ${AUDIT_PATH}
`;

  const policyYaml = `
rules:
  - name: "allow read"
    match:
      tool_name: "calendar.read"
    effect: allow
  - name: "default"
    match: {}
    effect: deny
`;

  writeFileSync(CONFIG_PATH, configYaml);
  writeFileSync(POLICY_PATH, policyYaml);

  // Mint valid token
  const now = Math.floor(Date.now() / 1000);
  token = await new jose.SignJWT({
    sub: "user-123",
    aud: "https://mcp.test.internal",
    iss: `http://127.0.0.1:${PORT_JWKS}`,
    iat: now,
    exp: now + 3600,
    agent_id: "agent-mcp",
  })
    .setProtectedHeader({ alg: "RS256" })
    .sign(privateKey);
});

afterAll(async () => {
  await new Promise<void>((resolve) => {
    jwksServer.close(() => resolve());
  });
  rmSync(TEMP_DIR, { recursive: true, force: true });
});

// Helper: wait for a single line response from MCP server
function readLine(proc: ChildProcessWithoutNullStreams): Promise<string> {
  return new Promise((resolve, reject) => {
    let output = "";
    const onData = (chunk: Buffer) => {
      output += chunk.toString("utf-8");
      const newlineIndex = output.indexOf("\n");
      if (newlineIndex !== -1) {
        proc.stdout.off("data", onData);
        resolve(output.slice(0, newlineIndex).trim());
      }
    };
    proc.stdout.on("data", onData);
    proc.stderr.on("data", (err) => {
      // Log errors on stderr during testing if needed
    });
  });
}

describe("Limekey MCP Server", () => {
  let proc: ChildProcessWithoutNullStreams;

  beforeAll(() => {
    proc = spawn("npx", ["tsx", "src/mcp.ts"], {
      env: {
        ...process.env,
        LIMEKEY_CONFIG: CONFIG_PATH,
      },
      shell: true,
    });
  });

  afterAll(() => {
    proc.kill();
  });

  it("handles initialize request successfully", async () => {
    const req = {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "test-client", version: "1.0.0" },
      },
    };
    proc.stdin.write(JSON.stringify(req) + "\n");

    const line = await readLine(proc);
    const res = JSON.parse(line);

    expect(res.jsonrpc).toBe("2.0");
    expect(res.id).toBe(1);
    expect(res.result.capabilities.tools).toBeDefined();
    expect(res.result.serverInfo.name).toBe("limekey-mcp");
  });

  it("handles tools/list request successfully", async () => {
    const req = {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
    };
    proc.stdin.write(JSON.stringify(req) + "\n");

    const line = await readLine(proc);
    const res = JSON.parse(line);

    expect(res.id).toBe(2);
    expect(res.result.tools).toBeDefined();
    expect(res.result.tools.length).toBe(1);
    expect(res.result.tools[0].name).toBe("authorize");
  });

  it("authorizes allowed tool execution", async () => {
    const req = {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "authorize",
        arguments: {
          token: token,
          tool_name: "calendar.read",
          arguments: { date: "2026-07-18" },
        },
      },
    };
    proc.stdin.write(JSON.stringify(req) + "\n");

    const line = await readLine(proc);
    const res = JSON.parse(line);

    expect(res.id).toBe(3);
    expect(res.result.isError).toBe(false);
    
    const content = JSON.parse(res.result.content[0].text);
    expect(content.decision).toBe("allow");
  });

  it("denies unlisted tool execution", async () => {
    const req = {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: {
        name: "authorize",
        arguments: {
          token: token,
          tool_name: "secrets.delete",
        },
      },
    };
    proc.stdin.write(JSON.stringify(req) + "\n");

    const line = await readLine(proc);
    const res = JSON.parse(line);

    expect(res.id).toBe(4);
    expect(res.result.isError).toBe(true);

    const content = JSON.parse(res.result.content[0].text);
    expect(content.decision).toBe("deny");
    expect(content.matched_rule).toBe("default");
    expect(content.reason).toBe('Operation denied by policy rule: "default"');
  });

  it("rejects request with missing token", async () => {
    const req = {
      jsonrpc: "2.0",
      id: 5,
      method: "tools/call",
      params: {
        name: "authorize",
        arguments: {
          tool_name: "calendar.read",
        },
      },
    };
    proc.stdin.write(JSON.stringify(req) + "\n");

    const line = await readLine(proc);
    const res = JSON.parse(line);

    expect(res.id).toBe(5);
    expect(res.result.isError).toBe(true);

    const content = JSON.parse(res.result.content[0].text);
    expect(content.error).toBe("missing_token");
  });
});
