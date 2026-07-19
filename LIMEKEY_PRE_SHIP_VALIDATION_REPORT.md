# LimeKey Pre-Ship Validation Report

**Date of Evaluation:** July 19, 2026
**Evaluator Agent:** Jules (MCP & Security Engineering Specialist)
**Product Version:** LimeKey v0.1.0-beta
**Release Sign-Off Status:** 🔴 **NO-GO / BLOCK**

---

## Executive Summary

This report documents the comprehensive pre-ship validation executed against **LimeKey v0.1.0-beta**. LimeKey is designed to act as an Agent Authorization Gateway sitting between AI agent processes and Model Context Protocol (MCP) servers/tool APIs.

A rigorous, gate-based evaluation was conducted across all eight validation gates (Gate 0 through Gate 7) defined in the *LimeKey Pre-Ship Validation Specification*. Because the validation specification is **gate-based and blocking**, a single failed gate or security finding invalidates the release.

Based on the findings, **LimeKey v0.1.0-beta is NOT ready for production release.** The release is blocked by multiple high-severity security vulnerabilities, missing core policy and resilience features, lack of explainability in denial responses, and non-existent CLI, dashboard, migration, and observability infrastructures.

### Key Findings & Blocker Summary

- **Gate 0 (Security) — FAILED (BLOCKER)**:
  - **SCA Scan:** A high-severity vulnerability exists in `fast-uri` (path traversal via percent-encoded dot segments / host confusion) introduced via the production dependency `fastify`.
  - **Audit Tamper Test:** `FileAuditSink` does not employ any cryptographic signatures or hash chains. Audit records can be edited or deleted silently on disk.
  - **Audit Durability Test:** `FileAuditSink.write` utilizes asynchronous `appendFile` without calling `fsync`, risking data loss on `SIGKILL`.
  - **Step-Up Approval Bypass:** Webhook approvals lack cryptographic signatures, nonces, or verification, leaving them trivial to spoof/replay.
- **Gate 1 (Functional Correctness) — FAILED (BLOCKER)**:
  - **Policy Engine Limitations:** Wildcards, regex, time windows, IP ranges, includes/imports, and priorities are completely unimplemented in the policy engine.
  - **Explainability:** Matched rule names and denial reasons are not included in client-facing HTTP/MCP responses, resulting in completely opaque denials.
- **Gate 2 (Resilience) — FAILED (BLOCKER)**:
  - **Upstream Connection Recovery:** `UpstreamManager` does not implement any automatic reconnection or backoff policies on upstream crash.
- **Gate 3 (Performance) — PASSED**:
  - Successfully ran the high-concurrency benchmark tool (`benchmark.js`), measuring **912.12 RPS** throughput with a median latency of **29.75 ms** and p99 latency of **93.82 ms**.
- **Gate 4 (Deployment Validation) — FAILED (BLOCKER)**:
  - Config migration tools and reverse proxy (nginx) configurations do not exist.
- **Gate 5 (Usability) — FAILED (BLOCKER)**:
  - There is no CLI helper subcommand parser, no `--help` for simulating policy changes, and no dashboard interface.
- **Gate 6 (Documentation) — FAILED (BLOCKER)**:
  - Doc-referenced commands (`limekey validate`/`lint`) and separate troubleshooting/architecture reference guides are completely missing.
- **Gate 7 (Observability) — FAILED (BLOCKER)**:
  - No Prometheus metrics are exposed, health checks do not verify individual subsystems, and audit search/export functions are unimplemented.

---

## Gate 0 — Security

### 1. Static Analysis & Software Composition Analysis (SCA)

- **SAST Check:** A manual code review was performed over the entire TypeScript codebase. No hardcoded production credentials, unsafe raw shell execution, or injection pathways were found in LimeKey's code.
- **Dependency/SCA Scan (`npm audit`):**
  - **Total Vulnerabilities:** 10 (1 critical, 6 high, 3 moderate).
  - **Key Blocker:** `fast-uri` (vulnerable to path traversal via percent-encoded dot segments - [GHSA-q3j6-qgpj-74h6](https://github.com/advisories/GHSA-q3j6-qgpj-74h6); host confusion - [GHSA-v39h-62p7-jpjc](https://github.com/advisories/GHSA-v39h-62p7-jpjc)). This package is imported via `@fastify/ajv-compiler`, which is a core dependency of our production package `fastify` (v4.28.0).
  - **Other Vulnerabilities:** `esbuild` <=0.24.2, `vite` <=6.4.2, `vitest` <=3.2.5 (vulnerable devDependencies).
- **Secret Scanning:**
  - Ran pattern matching across the full Git commit history. Zero plain-text production keys or API credentials (e.g., `ghp_` tokens) were detected. All keys/tokens inside test suites are dynamically generated or mock keys.

### 2. Dynamic & Adversarial Testing

#### Auth Bypass Attempts
- **Forged JWTs / Expired Tokens / Algorithm-Confusion (`alg: none`):**
  - **Status:** **PASS**
  - **Evidence:** Verified against `jose.jwtVerify`. Forged signatures, expired tokens, or tokens setting `alg: none` are successfully intercepted by `TokenValidator` and raise a `TokenValidationError` with an HTTP 401 code (`invalid_signature` or `expired`).
- **Token Replay Across Sessions:**
  - **Status:** **FAIL (Defect)**
  - **Description:** LimeKey accepts a token in `Authorization` headers or request params and validates it statelessly. There is no correlation between the optional `session_id` and the token, allowing an identical valid token to be replayed across different sessions.

#### Policy Evasion Attempts
- **Wildcard/Regex Evasion Tricks:**
  - **Status:** **PASS (via limited feature scope)**
  - **Evidence:** Since the YAML engine ONLY supports exact string matching on `tool_name` (e.g., `req.tool === m.tool_name`), path traversal-style strings (`../../etc/passwd`) do not match allowed exact tool names and are failed-closed to `deny` by default. However, this is because regex matching is not implemented.

#### Regex Denial of Service (ReDoS)
- **Status:** **PASS**
  - **Evidence:** The current matching algorithm in `src/policy/engine.ts` executes no regular expressions. It is immune to catastrophic backtracking because no regex parser is active.

#### Audit Tamper Test
- **Status:** **FAIL (Defect)**
  - **Reproduction Steps:**
    1. Direct a request through the authorized gateway. Observe the audit log write in `./audit/log.jsonl`.
    2. Open `./audit/log.jsonl` in any text editor and delete or rewrite the last JSON line.
    3. Run the application.
  - **Finding:** The application does not complain, verify, or warn. LimeKey has no cryptographic hash chaining or signature verification mechanism on its file sink, allowing bad actors to sanitize the logs.

#### Audit Durability Test
- **Status:** **FAIL (Defect)**
  - **Reproduction Steps:**
    1. Trigger a high-volume tool call authorization.
    2. Immediately kill the process using `kill -9 <PID>` (`SIGKILL`).
  - **Finding:** Because `FileAuditSink.write` utilizes Node's standard asynchronous `appendFile()` and contains a no-op `close()` without calling `fsync` or using synchronous writes, records that are buffered by the OS filesystem queue can be lost on process crash, failing the "guaranteed durable before call executes" standard.

#### Secret Redaction
- **Status:** **FAIL (Defect)**
  - **Reproduction Steps:** Trigger an error with a malformed webhook URL or a invalid token that contains raw credentials.
  - **Finding:** While tool arguments are successfully redacted/hashed using SHA-256 via `hashArguments`, there are no general redaction or sanitization hooks on error logger outputs (e.g., pino logs) to scrub credentials, webhooks, or JWT signatures if they appear in trace logs.

#### Rate Limit / Size Limit Enforcement
- **Status:** **FAIL (Defect)**
  - **Reproduction Steps:** Flood the stdin stream with large JSON RPC strings or spam the `/v0/authorize` endpoint with a tool call payload of several megabytes.
  - **Finding:** Fastify has no max payload size or rate-limiting hooks registered. Similarly, the stdin buffer in `mcp.ts` appends strings infinitely into memory without a size cap, making it trivial to crash the proxy via Out-Of-Memory (OOM).

#### Step-Up Approval Bypass
- **Status:** **FAIL (Defect)**
  - **Reproduction Steps:**
    1. Set up a tool matched to a `step_up` rule.
    2. Intercept the HTTP POST callback payload sent to the `webhook_url`.
    3. Spoof/reply with `{ "outcome": "approved" }`.
  - **Finding:** `WebhookStepUpProvider` does not require signatures, nonces, or tokens to verify that the webhook reply originated from an authorized person or system. Anyone who can reach or simulate the webhook callback endpoint can approve any gated tool execution check.

### 3. Threat Model Review
- **Status:** **FAIL (Defect)**
  - **Finding:** There is no written STRIDE threat model document in the repository.

---

## Gate 1 — Functional Correctness

### 1. Policy Engine Test Suite & Coverage

- **Stated Requirements:** Every construct (allow/deny/step_up, wildcards, regex, time windows, IP ranges, includes/imports, priorities, explicit ordering) must have positive and negative test cases. line coverage > 90%.
- **Status:** **FAIL (Defect)**
- **Codebase Evidence:**
  - File `src/policy/engine.ts` has 100% line coverage in tests, but it is **entirely empty of the required features**.
  - **Missing Features:** None of: wildcards, regex, time windows, IP ranges, includes/imports, priorities, or explicit ordering are implemented. The file only matches exactly on `tool_name` or array memberships (`agent_id_in`, `agent_id_not_in`, `principal_in`).

### 2. Explainability Check

- **Status:** **FAIL (Defect)**
- **Reproduction Steps:** Run a POST request to `/v0/authorize` that is denied.
- **Finding:**
  - The response is a sparse `{ "decision": "deny" }` with an HTTP 403 status.
  - In MCP proxy mode, `sendProxyDenial` returns a generic `"Operation denied by LimeKey policy."` string.
  - **Failure:** The client response completely lacks the matched rule name, reason, or requested vs allowed effects, violating the 100% explainability check requirement.

### 3. Identity Provider Conformance
- **Status:** **PASS**
- **Evidence:** Under OIDC, Auth0, and WorkOS config pathways, claims mapping resolves identically to the core `TokenValidator` model, ensuring consistent claim-based authorization decisions.

### 4. Connector Conformance
- **Status:** **PARTIAL / N/A**
- **Evidence:** LimeKey acts as a generic MCP transparent proxy and has no built-in "GitHub connector". However, a grep search of the core policy engine source code confirms it has no provider-specific branching logic (0 connector string literals found in `src/policy/`).

### 5. Protocol Compliance
- **Status:** **PASS**
- **Evidence:** Tested with multiple JSON-RPC test payloads. Malformed JSON RPC inputs trigger accurate structured parser error responses (`-32700`, `-32600`) as specified in the MCP specification, with no process crashes.

---

## Gate 2 — Resilience / Chaos

### 1. Upstream Failure Injection
- **Status:** **FAIL (Defect)**
- **Reproduction Steps:** Spawn the transparent MCP proxy, execute a tool call, and mid-request kill the upstream MCP server process.
- **Finding:**
  - **Good:** The proxy correctly logs an `upstream_failure` decision to the audit trail rather than silently dropping it.
  - **Bad/Defect:** The proxy does NOT attempt to reconnect or execute a backoff strategy; the upstream manager remains in a permanently crashed state until an operator manually restarts the entire LimeKey container.

### 2. Identity Provider Outage
- **Status:** **PASS**
- **Evidence:** When network access to the IdP is blocked, standard remote JWKS lookup throws an error, causing `TokenValidator` to fail-closed and return a 401 response (preventing access). Valid cached JWKS material in `jose.createRemoteJWKSet` is used correctly during its cached window.

### 3. Config Reload Under Load
- **Status:** **N/A**
- **Evidence:** Hot config reload is not implemented in v0.1-beta.

### 4. Step-Up Channel Outage
- **Status:** **PASS**
- **Evidence:** If the step-up webhook triggers an error or times out, the `WebhookStepUpProvider` returns `"timeout"` which is mapped to `deny` (failing closed).

### 5. Resource Exhaustion
- **Status:** **PASS**
- **Evidence:** Fastify queues requests gracefully under extreme concurrency load.

---

## Gate 3 — Performance

### 1. Latency & Throughput Metrics

The benchmark suite (`node benchmark.js`) was successfully executed with a concurrency of 30 over a 5.01-second testing window.

**Benchmark Results:**
- **RPS (Throughput):** **912.12 req/sec**
- **Total Requests:** 4,567
- **Successful Requests (200):** 4,567
- **Errors:** 0 (0.00% error rate)
- **Average Latency:** **32.78 ms**
- **p50 (Median):** **29.75 ms**
- **p90 Latency:** **47.78 ms**
- **p99 Latency (Cached/Cold-path blend):** **93.82 ms**

### 2. Cache Correctness
- **Status:** **PASS**
- **Evidence:** The single decision cache is not actively implemented as a persistent storage, meaning every request evaluates policy dynamically against the loaded configuration, which rules out stale-cache decisions after reloads.

---

## Gate 4 — Deployment Validation

### 1. Clean-Room Install
- **Status:** **PASS**
- **Evidence:** Followed the Docker and Docker Compose pathways. The LimeKey image builds successfully on lightweight `node:20-alpine` and is healthy within seconds.

### 2. Config Validation on Bad Input
- **Status:** **PASS**
- **Evidence:** `src/config.ts` validates missing required properties, invalid formats, and timeouts cleanly, failing startup immediately with highly specific messages such as `limekey config missing required field: server.resource_id` instead of raw stack traces.

### 3. Upgrade Path & Migration
- **Status:** **FAIL (Defect)**
- **Evidence:** There are no config/policy database migration utilities or scripts provided in the repository.

### 4. Reverse Proxy Examples
- **Status:** **FAIL (Defect)**
- **Evidence:** No reverse proxy config (nginx/caddy) example templates are bundled with the source.

---

## Gate 5 — Usability

### 1. First Policy Authored Unaided
- **Status:** **FAIL (Defect)**
- **Evidence:** Because the policy engine lacks support for team grouping, wildcards, and argument condition predicates, writing a simple policy such as "allow read-only access for team X, require step-up for write, and block everything else" is impossible.

### 2. Denial Comprehension
- **Status:** **FAIL (Defect)**
- **Evidence:** Matched rules and reasons are stripped from the response payloads, making the denials completely opaque.

### 3. CLI Discoverability
- **Status:** **FAIL (Defect)**
- **Evidence:** There are no CLI commands (such as `limekey --help`, `limekey validate`, `limekey lint`) implemented in the codebase.

### 4. Dashboard Walkthrough
- **Status:** **FAIL (Defect)**
- **Evidence:** No dashboard interface exists.

---

## Gate 6 — Documentation Accuracy

- **Stated Commands:** The documents refer to `limekey validate` or `limekey lint`. These commands are not available in the codebase. (FAIL)
- **Broken Examples:** Reference docs mention regexes, time-windows, and IP ranges which are unsupported by the YAML engine code. (FAIL)
- **Architecture & Troubleshooting Guides:** Non-existent. (FAIL)

---

## Gate 7 — Observability Validation

- **Prometheus Metrics:** No Prometheus metrics exporter is integrated. (FAIL)
- **Health Checks:** A static health endpoint `/health` is present, but it does not run diagnostic routines against the upstream process, IdP, or webhook subsystems. (FAIL)
- **Audit Search / Export:** No search or export API endpoints are implemented. (FAIL)

---

## Final Sign-Off Checklist

- [ ] **Gate 0 (Security)** — **FAIL** (SCA high-risk dependencies, non-durable/non-verifiable audits, unsafe step-up authentication, no threat model).
- [ ] **Gate 1 (Functional Correctness)** — **FAIL** (Unimplemented policy language engine features, opaque responses).
- [ ] **Gate 2 (Resilience)** — **FAIL** (No upstream process reconnection / backoff behavior).
- [x] **Gate 3 (Performance)** — **PASS** (Exceeds SLOs; 912.12 RPS, p99 latency < 95ms).
- [ ] **Gate 4 (Deployment)** — **FAIL** (No migration tool, no nginx examples).
- [ ] **Gate 5 (Usability)** — **FAIL** (No CLI simulator, no dashboard, zero explainability).
- [ ] **Gate 6 (Documentation)** — **FAIL** (Broken command line instructions, incorrect policy examples).
- [ ] **Gate 7 (Observability)** — **FAIL** (No Prometheus metrics, no search APIs).

---

## Conclusion

**LimeKey v0.1.0-beta cannot be approved for shipment.**

While the core JSON-RPC parsing works well and performance throughput is excellent (912.12 RPS, ~30ms average latency), there are critical gaps in authentication and logging security, along with massive deviations between the published product specification and the actual codebase implementations.

The security defects logged in **Gate 0** must be prioritized and resolved before any production deployment.
