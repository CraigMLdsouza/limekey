# Limekey — Agent Authorization Gateway
### Protocol & Architecture Spec — v0.1 (draft)

## 1. What Limekey is

Limekey is a self-hosted, identity-provider-agnostic **authorization gateway**
for AI agents. It sits between an agent (or agent framework) and the tools /
MCP servers / APIs it calls, and answers one question on every single call:

> "Is this agent, acting on behalf of this principal, allowed to call this
> tool, with these arguments, right now?"

It does **not** issue identity. It does **not** replace your CIAM/IdP
(Auth0, WorkOS, Ory, Stytch, your own OIDC server). It sits in front of
whatever you already use and adds the parts that are missing today:
fine-grained per-tool-call policy, human step-up approval, and a unified
audit trail — regardless of which IdP or which MCP servers are involved.

Positioning: Limekey is to agent authorization what Envoy is to service
mesh traffic — a neutral, composable proxy, not a monolith.

## 2. Design principles

1. **Protocol-first, vendor-neutral.** Limekey implements open specs
   (OAuth 2.1, RFC 9728, RFC 8707, MCP's auth profile). It never requires a
   specific IdP.
2. **Deny by default.** No policy match → deny. Silence is not permission.
3. **Every decision is logged.** Allow, deny, and step-up events are all
   audit events. Audit is not a paid add-on — it's core.
4. **Separate "authenticated" from "authorized."** A valid token proves who
   is asking. A policy decision proves what they may do. Limekey treats
   these as two distinct, composable stages.
5. **Human-in-the-loop is a first-class primitive**, not a UI bolted on top.
   Sensitive tool calls can require a real-time human approval event before
   the token is considered valid for that call.

## 3. Scope of v0.1

In scope:
- Acting as an OAuth 2.1 **resource server** in front of one or more MCP
  servers (per the 2026-07-28 MCP auth profile).
- RFC 9728 (OAuth 2.0 Protected Resource Metadata) discovery endpoint.
- RFC 8707 (Resource Indicators) enforcement — reject tokens not scoped to
  this resource.
- A pluggable policy engine (ship a simple YAML/JSON rule format in v0.1;
  Rego/OPA support in v0.2).
- Structured audit log (local file + pluggable sink).
- A step-up approval hook (webhook-based in v0.1; CIBA-compliant in v0.2).
- Adapters for validating tokens issued by: generic OIDC, Auth0, WorkOS.

Out of scope for v0.1 (tracked for later versions):
- Token *issuance* (Limekey validates, it doesn't mint).
- Agent-to-agent (A2A) delegation chains / DID-VC verification.
- Cross-organization trust (TRAIL, MCP-I) — v0.3 target.
- Multi-region / HA deployment topologies.

## 4. Core concepts

### 4.1 Principal
The human or service on whose behalf an agent is acting. Identified by the
`sub` claim of the validated access token.

### 4.2 Agent identity
A separate, explicit identity for the *agent process itself*, distinct from
the principal. Carried as a custom claim (`agent_id`) or a certified client
ID from Dynamic Client Registration / a Client ID Metadata Document.
Limekey requires this to be present and non-empty — "agent acting as
anonymous" is not a supported mode.

### 4.3 Resource
The MCP server / tool endpoint being protected. Identified by its resource
URI, matched against RFC 8707 `resource` claims/parameters on the token.

### 4.4 Tool call
The unit of authorization. A tool call has: `agent_id`, `principal`,
`resource`, `tool_name`, `arguments` (as a JSON object), and `context`
(time, session, prior calls in this session if tracked).

### 4.5 Policy
A rule that maps a tool call to `allow`, `deny`, or `step_up`. Policies are
evaluated in order; first match wins; default is `deny`.

### 4.6 Step-up event
A synchronous pause where Limekey blocks the call, notifies a human
(webhook in v0.1), and waits for an explicit approve/deny before letting the
call (or the whole session) proceed. Approval is itself logged as an audit
event and, where the upstream IdP supports it, should be translated into a
verifiable authorization event (e.g. CIBA) rather than trusted as a bare
UI click.

## 5. Request flow

```
Agent
  │  MCP tool call + Bearer token
  ▼
┌─────────────────────────────────────────────┐
│                  LIMEKEY                     │
│                                               │
│  1. Discovery                                │
│     GET /.well-known/oauth-protected-resource │
│     (RFC 9728) → tells clients which          │
│     authorization server to use               │
│                                               │
│  2. Token validation                         │
│     - signature / issuer / expiry            │
│     - RFC 8707 `resource` matches this server │
│     - agent_id claim present                  │
│                                               │
│  3. Policy evaluation                        │
│     match(agent_id, principal, tool_name,     │
│           arguments, context)                 │
│       → allow | deny | step_up                │
│                                               │
│  4. [if step_up] pause, notify, await         │
│     approval or timeout → deny                │
│                                               │
│  5. Audit log write (always, regardless        │
│     of outcome)                               │
│                                               │
│  6. Forward request to resource, or reject    │
└─────────────────────────────────────────────┘
                    │
                    ▼
            MCP server / Tool / API
```

## 6. Config schema (v0.1)

```yaml
# limekey.config.yaml
server:
  listen: 0.0.0.0:8443
  resource_id: "https://tools.acme.internal"   # RFC 8707 resource identifier

identity:
  provider: generic_oidc   # generic_oidc | auth0 | workos
  issuer: "https://auth.acme.com/"
  jwks_uri: "https://auth.acme.com/.well-known/jwks.json"
  agent_id_claim: "agent_id"
  required_audience: "https://tools.acme.internal"

policy:
  engine: yaml              # yaml (v0.1) | rego (v0.2)
  source: ./policies/example.yaml
  default: deny

step_up:
  mode: webhook             # webhook (v0.1) | ciba (v0.2)
  webhook_url: "https://approvals.acme.internal/hook"
  timeout_seconds: 120
  on_timeout: deny

audit:
  sink: file                # file | http | (pluggable)
  path: ./audit/log.jsonl
```

## 7. Policy rule format (v0.1)

```yaml
# policies/example.yaml
rules:
  - name: "allow read-only calendar reads"
    match:
      tool_name: "calendar.read"
    effect: allow

  - name: "require approval for sends"
    match:
      tool_name: "email.send"
    effect: step_up

  - name: "block finance writes from non-finance agents"
    match:
      tool_name: "ledger.write"
      agent_id_not_in: ["finance-agent-01"]
    effect: deny

  - name: "default"
    match: {}
    effect: deny
```

## 8. Audit log schema (v0.1)

Every decision emits one JSON line:

```json
{
  "ts": "2026-07-17T09:03:21Z",
  "agent_id": "finance-agent-01",
  "principal": "user_8f2c...",
  "resource": "https://tools.acme.internal",
  "tool_name": "ledger.write",
  "arguments_hash": "sha256:...",
  "decision": "deny",
  "matched_rule": "block finance writes from non-finance agents",
  "step_up": null,
  "latency_ms": 4
}
```

`arguments_hash` is logged instead of raw arguments by default (avoids
leaking PII into audit storage); raw argument logging is opt-in per policy
rule.

## 9. Versioning / roadmap

- **v0.1** — YAML policy engine, webhook step-up, file audit sink, generic
  OIDC + Auth0 + WorkOS token validation. Ships as a single Docker
  container.
- **v0.2** — Rego/OPA policy engine, CIBA-based step-up, pluggable audit
  sinks (HTTP, S3, Kafka), Dynamic Client Registration / Client ID
  Metadata Document support.
- **v0.3** — Agent-to-agent (A2A) delegation chains, DID/VC verification
  for cross-org calls, TRAIL / MCP-I interop.

## 10. Non-goals

Limekey will not become an IdP, a secrets manager, or a full CIAM
replacement. Its entire value is being the thin, boring, auditable layer
that composes with whatever identity stack you already run.
