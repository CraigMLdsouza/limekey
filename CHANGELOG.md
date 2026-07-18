# Changelog

All notable changes to Limekey will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-07-17

### Added

- **Authorization gateway** — `POST /v0/authorize` decision endpoint that
  validates tokens, evaluates policy, triggers step-up approval, and logs
  every decision.
- **RFC 9728 discovery** — `GET /.well-known/oauth-protected-resource`
  tells MCP clients which authorization server to use.
- **RFC 8707 enforcement** — tokens are rejected if their audience doesn't
  match this server's resource identifier.
- **YAML policy engine** — first-match-wins rules with `allow`, `deny`,
  and `step_up` effects. Match on `tool_name`, `agent_id_in`,
  `agent_id_not_in`, `principal_in`, or catch-all.
- **Webhook step-up approval** — sensitive tool calls pause and wait for
  a human to approve/deny via webhook, with configurable timeout.
- **Structured audit log** — every decision (allow, deny, step-up) written
  as a JSONL line. Arguments are SHA-256 hashed by default to prevent PII
  leakage.
- **IdP adapters** — factory functions for generic OIDC, Auth0, and WorkOS.
  Auth0 adapter warns on unnamespaced custom claims.
- **Health check** — `GET /health` for readiness probes.
- **CORS support** — browser-based MCP clients can call discovery and
  authorization endpoints.
- **Graceful shutdown** — SIGTERM/SIGINT handlers close the server and
  flush the audit sink.
- **Docker support** — multi-stage Dockerfile and docker-compose.yml.
- **87 tests** across 7 test files covering config, token validation,
  policy engine, audit, webhook step-up, and integration.
