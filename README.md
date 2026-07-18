<p align="center">
  <img src="https://raw.githubusercontent.com/limekey-dev/limekey/main/logo.png" alt="Limekey Logo" width="150" style="border-radius: 12px; margin-bottom: 20px;" />
</p>

# Limekey — Agent Authorization Gateway

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI Status](https://img.shields.io/github/actions/workflow/status/limekey-dev/limekey/ci.yml?branch=main)](https://github.com/limekey-dev/limekey/actions)
[![Version](https://img.shields.io/badge/version-0.1.0--beta-green.svg)]()
[![Docker Pulls](https://img.shields.io/docker/pulls/limekey/limekey?color=blue)]()

> **The missing authorization boundary for AI Agents.** Sits between your agent processes and your MCP servers / tool APIs to answer: *"Is this agent, acting on behalf of this user, authorized to execute this tool call with these exact arguments right now?"*

---

## Why Limekey?

AI agents (built with LangChain, CrewAI, AutoGPT, or raw MCP clients) are increasingly given write access to databases, Slack workspace APIs, transactional email platforms, and cloud infrastructure. 

However, LLMs are non-deterministic and susceptible to **prompt injection**, **jailbreaking**, and **hallucinations**. Direct tool access exposes organizations to catastrophic risks (data exfiltration, unauthorized transactions, accidental resource deletion).

**Limekey solves this by decoupling authorization from execution.** It acts as a policy decision proxy that applies zero-trust rules to every single tool execution.

```mermaid
sequenceDiagram
    autonumber
    participant Agent as AI Agent (MCP Client)
    participant Limekey as Limekey Gateway
    participant IdP as Identity Provider (OIDC/Auth0/WorkOS)
    participant Webhook as Approval Hook (Slack/Opsgenie)
    participant Tool as Target Tool (MCP Server)

    Agent->>IdP: Authenticate & get Access Token (with principal + agent_id)
    IdP-->>Agent: Return JWT
    Agent->>Limekey: POST /v0/authorize (Bearer Token + tool name + arguments)
    Note over Limekey: 1. Validate Token Signature/Issuer<br/>2. Enforce RFC 8707 Resource Scope<br/>3. Evaluate YAML Policies
    alt Policy = Allow
        Limekey-->>Agent: HTTP 200 (Allow)
        Agent->>Tool: Execute Tool
    else Policy = Step-up Required
        Limekey->>Webhook: Trigger approval request
        Note over Webhook: Human reviews tool call & click Approve
        Webhook-->>Limekey: Callback: approved
        Limekey-->>Agent: HTTP 200 (Allow)
        Agent->>Tool: Execute Tool
    else Policy = Deny (or Timeout)
        Limekey-->>Agent: HTTP 403 (Deny)
        Note over Agent: Halt execution / handle error
    end
```

---

## Core Capabilities

*   **🔒 Decoupled Agent Identity (RFC 8707 + OAuth 2.1):** Separate the *human user* (`sub` claim) from the *agent instance* (`agent_id` custom claim). Ensure a token minted for a code-writer agent cannot be replayed by a calendar-scheduling agent.
*   **⚙️ Declarative, Auditable Rules:** Simple, human-readable YAML policy syntax. Express fine-grained conditions like *"Allow agent `support-bot` to read database tables, but require human step-up approval to write, and deny drop table actions entirely."*
*   **👥 Human-in-the-Loop Webhooks:** Pause execution and request manual approval for high-risk actions. Integrates easily with Slack, PagerDuty, Teams, or your own approval portals.
*   **🛡️ Privacy-First Audit Logs:** Logs every single check (`allow`, `deny`, `step_up`) to a structured JSONL sink. By default, tool arguments are SHA-256 hashed so that sensitive user PII, API tokens, or keys never leak into your log management systems.
*   **🔌 Enterprise IdP Integration:** Out-of-the-box support for verifying tokens from Auth0, WorkOS, and generic OIDC providers.

---

## Quickstart

### 1. Installation

Clone and install dependencies:
```bash
git clone https://github.com/limekey-dev/limekey.git
cd limekey
npm install
```

### 2. Configuration

Copy the example configuration:
```bash
cp limekey.config.example.yaml limekey.config.yaml
```

Edit `limekey.config.yaml` to specify your OIDC/Auth0/WorkOS tenant credentials:
```yaml
server:
  listen: 0.0.0.0:8443
  resource_id: "https://api.acme.com/mcp"

identity:
  provider: auth0
  issuer: "https://auth.acme.com/"
  jwks_uri: "https://auth.acme.com/.well-known/jwks.json"
  agent_id_claim: "https://limekey.dev/agent_id"
  required_audience: "https://api.acme.com/mcp"

policy:
  engine: yaml
  source: ./policies/example.yaml
  default: deny

step_up:
  mode: webhook
  webhook_url: "https://approvals.acme.com/hook"
  timeout_seconds: 60
  on_timeout: deny

audit:
  sink: file
  path: ./audit/log.jsonl
```

### 3. Run

Start the gateway in development mode with hot-reloading:
```bash
npm run dev
```

For production deployments, compile and start the optimized JavaScript bundle:
```bash
npm run build
npm start
```

---

## Docker Deployment

Limekey is distributed as a lightweight Docker container, optimized for minimal resource footprints (built on `node:20-alpine`).

Run with Docker Compose:
```bash
docker-compose up --build -d
```

The compose setup exposes port `8443` and configures a healthcheck checking `/health`.

---

## API Reference

### `GET /health`

Used for orchestrator health checks.

**Response (200 OK):**
```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

### `GET /.well-known/oauth-protected-resource`

Implements **RFC 9728** discovery. Lets MCP clients auto-discover which identity provider to use before making requests.

**Response (200 OK):**
```json
{
  "resource": "https://api.acme.com/mcp",
  "authorization_servers": [
    "https://auth.acme.com/"
  ],
  "bearer_methods_supported": [
    "header"
  ]
}
```

### `POST /v0/authorize`

Called by the agent framework or MCP client prior to executing a tool.

**Headers:**
```http
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ik...
Content-Type: application/json
```

**Request Body:**
```json
{
  "tool_name": "slack.post_message",
  "arguments": {
    "channel": "#general",
    "text": "Hello world from the agent!"
  },
  "session_id": "sess_8f2c3d9a"
}
```

**Responses:**

*   **200 OK (Allowed):**
    ```json
    { "decision": "allow" }
    ```
*   **401 Unauthorized:** Invalid signature, expired token, or missing `agent_id` claim.
*   **403 Forbidden (Denied):**
    ```json
    {
      "decision": "deny",
      "rule": "block-general-slack-channel-writes"
    }
    ```

---

## Writing Policies

Policies are evaluated from top to bottom (first-match-wins). If no policy matches, the request is denied by the catch-all default rule.

Example policy (`policies/example.yaml`):
```yaml
rules:
  - name: "allow read-only calendar reads"
    match:
      tool_name: "calendar.read"
    effect: allow

  - name: "require approval for sends"
    match:
      tool_name: "email.send"
    effect: step_up

  - name: "block ledger writes from non-finance agents"
    match:
      tool_name: "ledger.write"
      agent_id_not_in: ["finance-agent-01"]
    effect: deny

  - name: "default catch-all"
    match: {}
    effect: deny
```

---

## Contributing

We want Limekey to be standard, boring internet security infrastructure. PRs adding new identity providers, additional audit log sinks (S3, Kafka), and OPA engine support are highly welcomed.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for local development setup and style guidelines.

## Roadmap & Scope

*   **v0.1 (Current):** YAML rule engine, webhook-based human approval, file audit sink, standard OIDC/Auth0/WorkOS token validation.
*   **v0.2:** Rego/OPA policy engine support, CIBA-compliant (Client-Initiated Backchannel Authentication) step-up approval, pluggable AWS S3/Kafka audit logs.
*   **v0.3:** Agent-to-agent delegation chains (VCs) and cross-org zero-trust routing.

## License

Limekey is open-source software licensed under the [Apache 2.0 License](./LICENSE).
