import { spawn } from "node:child_process";
import { writeFileSync, unlinkSync, mkdirSync, rmSync } from "node:fs";
import * as http from "node:http";
import * as jose from "jose";

const LIMEKEY_DIR = process.cwd();
const CONFIG_PATH = `${LIMEKEY_DIR}/limekey.config.benchmark.yaml`;
const POLICY_PATH = `${LIMEKEY_DIR}/policies/benchmark.yaml`;
const AUDIT_DIR = `${LIMEKEY_DIR}/audit`;

const PORT_JWKS = 9000;
const PORT_LIMEKEY = 8443;
const TEST_DURATION_MS = 5000;
const CONCURRENCY = 30;

// Setup mock configurations
const configYaml = `
server:
  listen: 127.0.0.1:${PORT_LIMEKEY}
  resource_id: "https://benchmark.limekey.dev"

identity:
  provider: generic_oidc
  issuer: "http://127.0.0.1:${PORT_JWKS}"
  jwks_uri: "http://127.0.0.1:${PORT_JWKS}/.well-known/jwks.json"
  agent_id_claim: "agent_id"
  required_audience: "https://benchmark.limekey.dev"

policy:
  engine: yaml
  source: ./policies/benchmark.yaml
  default: deny

step_up:
  mode: webhook
  webhook_url: "http://127.0.0.1:9001/approve"
  timeout_seconds: 5
  on_timeout: deny

audit:
  sink: file
  path: ./audit/benchmark.jsonl
`;

const policyYaml = `
rules:
  - name: "allow calendar reads"
    match:
      tool_name: "calendar.read"
    effect: allow
  - name: "default"
    match: {}
    effect: deny
`;

async function run() {
  console.log("=== Limekey Benchmark Setup ===");

  // 1. Generate RSA key pair for JWT signing
  const { publicKey, privateKey } = await jose.generateKeyPair("RS256");
  const publicJwk = await jose.exportJWK(publicKey);
  const jwksJson = JSON.stringify({ keys: [publicJwk] });

  // 2. Start mock JWKS server
  console.log(`Starting mock JWKS server on port ${PORT_JWKS}...`);
  const jwksServer = http.createServer((req, res) => {
    if (req.url === "/.well-known/jwks.json") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(jwksJson);
    } else {
      res.writeHead(404).end();
    }
  });
  jwksServer.listen(PORT_JWKS, "127.0.0.1");

  // 3. Write temp config files
  writeFileSync(CONFIG_PATH, configYaml);
  writeFileSync(POLICY_PATH, policyYaml);

  // 4. Mint test JWT token
  const now = Math.floor(Date.now() / 1000);
  const token = await new jose.SignJWT({
    sub: "user-benchmark",
    aud: "https://benchmark.limekey.dev",
    iss: `http://127.0.0.1:${PORT_JWKS}`,
    iat: now,
    exp: now + 3600,
    agent_id: "benchmark-agent",
  })
    .setProtectedHeader({ alg: "RS256" })
    .sign(privateKey);

  // 5. Spawn Limekey Gateway process
  console.log("Spawning Limekey server...");
  const limekeyProc = spawn("node", ["dist/index.js"], {
    cwd: LIMEKEY_DIR,
    env: {
      ...process.env,
      LIMEKEY_CONFIG: CONFIG_PATH,
    },
    shell: false,
  });

  // Handle stream logs to print errors
  limekeyProc.stdout?.pipe(process.stdout);
  limekeyProc.stderr?.pipe(process.stderr);

  // Wait for Limekey to boot
  console.log("Waiting for Limekey to become healthy...");
  let healthy = false;
  for (let i = 0; i < 20; i++) {
    await new Promise((r) => setTimeout(r, 250));
    try {
      const res = await fetch(`http://127.0.0.1:${PORT_LIMEKEY}/health`);
      if (res.status === 200) {
        healthy = true;
        break;
      }
    } catch {}
  }

  if (!healthy) {
    console.error("Error: Limekey server failed to start or report healthy.");
    jwksServer.close();
    limekeyProc.kill();
    cleanupFiles();
    process.exit(1);
  }
  console.log("Limekey is healthy. Starting load test...");

  // 6. Benchmark execution
  const start = Date.now();
  let totalRequests = 0;
  let successfulRequests = 0;
  let errorRequests = 0;
  const latencies = [];

  const runWorker = async () => {
    while (Date.now() - start < TEST_DURATION_MS) {
      const reqStart = performance.now();
      try {
        const res = await fetch(`http://127.0.0.1:${PORT_LIMEKEY}/v0/authorize`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
          },
          body: JSON.stringify({
            tool_name: "calendar.read",
            arguments: { date: "2026-07-17" },
          }),
        });

        const latency = performance.now() - reqStart;
        latencies.push(latency);
        totalRequests++;

        if (res.status === 200) {
          successfulRequests++;
        } else {
          errorRequests++;
        }
      } catch (err) {
        totalRequests++;
        errorRequests++;
      }
    }
  };

  // Launch parallel workers
  console.log(`Running benchmark with concurrency=${CONCURRENCY} for ${TEST_DURATION_MS / 1000}s...`);
  const workers = Array.from({ length: CONCURRENCY }, () => runWorker());
  await Promise.all(workers);

  const durationSec = (Date.now() - start) / 1000;
  console.log("\n=== Benchmark Results ===");
  console.log(`Duration:           ${durationSec.toFixed(2)} seconds`);
  console.log(`Total Requests:     ${totalRequests}`);
  console.log(`Successful (200):   ${successfulRequests}`);
  console.log(`Errors/Non-200:     ${errorRequests}`);
  console.log(`RPS (Throughput):   ${(totalRequests / durationSec).toFixed(2)} req/sec`);

  if (latencies.length > 0) {
    latencies.sort((a, b) => a - b);
    const avg = latencies.reduce((a, b) => a + b, 0) / latencies.length;
    const p50 = latencies[Math.floor(latencies.length * 0.5)];
    const p90 = latencies[Math.floor(latencies.length * 0.90)];
    const p99 = latencies[Math.floor(latencies.length * 0.99)];

    console.log(`Average Latency:    ${avg.toFixed(2)} ms`);
    console.log(`p50 (Median):       ${p50.toFixed(2)} ms`);
    console.log(`p90:                ${p90.toFixed(2)} ms`);
    console.log(`p99:                ${p99.toFixed(2)} ms`);
  }

  // 7. Cleanup
  console.log("\nTearing down servers...");
  if (typeof jwksServer.closeAllConnections === "function") {
    jwksServer.closeAllConnections();
  }
  jwksServer.close();
  
  // Kill Limekey process cleanly
  limekeyProc.kill("SIGKILL");
  await new Promise((r) => setTimeout(r, 1000));
  
  cleanupFiles();
  console.log("Cleanup complete. Done!");
}

function cleanupFiles() {
  try { unlinkSync(CONFIG_PATH); } catch {}
  try { unlinkSync(POLICY_PATH); } catch {}
  try { rmSync(AUDIT_DIR, { recursive: true, force: true }); } catch {}
}

run().catch(console.error);
