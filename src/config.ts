import { readFileSync } from "node:fs";
import yaml from "js-yaml";

export interface LimekeyConfig {
  server: { listen: string; resource_id: string };
  identity: {
    provider: "generic_oidc" | "auth0" | "workos";
    issuer: string;
    jwks_uri: string;
    agent_id_claim: string;
    required_audience: string;
  };
  policy: {
    engine: "yaml" | "rego";
    source: string;
    default: "allow" | "deny";
  };
  step_up: {
    mode: "webhook" | "ciba";
    webhook_url: string;
    timeout_seconds: number;
    on_timeout: "allow" | "deny";
  };
  audit: {
    sink: "file" | "http";
    path: string;
  };
  /** Present only in proxy mode. When set, Limekey spawns this process and
   *  acts as a transparent MCP policy enforcement proxy in front of it. */
  upstream?: UpstreamConfig;
}

export interface UpstreamConfig {
  /** Executable to spawn (e.g. "npx"). */
  command: string;
  /** Arguments passed to the command (e.g. ["-y", "@modelcontextprotocol/server-github"]). */
  args: string[];
  /** Keys to forward from Limekey's env to the upstream process. Secrets stay
   *  out of the config file — they live in the process environment. */
  passthrough_env?: string[];
  /** Seconds to wait for upstream initialize handshake. Default: 10. */
  startup_timeout: number;
  /** Per-request timeout in seconds. Default: 30. */
  request_timeout: number;
}

export interface ListenAddress {
  host: string;
  port: number;
}

/**
 * Parse a "host:port" listen string into its components.
 * Accepts "0.0.0.0:8443", ":8443" (default host 0.0.0.0), or
 * just "8443" (port only).
 */
export function parseListenAddress(listen: string): ListenAddress {
  const parts = listen.split(":");
  if (parts.length === 2) {
    return {
      host: parts[0] || "0.0.0.0",
      port: parseInt(parts[1], 10),
    };
  }
  if (parts.length === 1) {
    const port = parseInt(parts[0], 10);
    if (!isNaN(port)) {
      return { host: "0.0.0.0", port };
    }
  }
  throw new Error(
    `invalid server.listen format "${listen}" — expected "host:port" (e.g. "0.0.0.0:8443")`,
  );
}

export function loadConfig(path: string): LimekeyConfig {
  const raw = readFileSync(path, "utf-8");
  const config = yaml.load(raw) as LimekeyConfig;
  applyDefaults(config);
  validate(config);
  return config;
}

/** Fill in sensible defaults so minimal configs still work. */
function applyDefaults(config: LimekeyConfig): void {
  if (!config.server) config.server = {} as LimekeyConfig["server"];
  config.server.listen ??= "0.0.0.0:8443";

  if (!config.identity) config.identity = {} as LimekeyConfig["identity"];
  config.identity.provider ??= "generic_oidc";
  config.identity.agent_id_claim ??= "agent_id";

  if (!config.policy) config.policy = {} as LimekeyConfig["policy"];
  config.policy.engine ??= "yaml";
  config.policy.default ??= "deny";

  if (!config.step_up) config.step_up = {} as LimekeyConfig["step_up"];
  config.step_up.mode ??= "webhook";
  config.step_up.timeout_seconds ??= 120;
  config.step_up.on_timeout ??= "deny";

  if (!config.audit) config.audit = {} as LimekeyConfig["audit"];
  config.audit.sink ??= "file";

  if (config.upstream) {
    config.upstream.startup_timeout ??= 10;
    config.upstream.request_timeout ??= 30;
    config.upstream.args ??= [];
    config.upstream.passthrough_env ??= [];
  }
}

function validate(config: LimekeyConfig): void {
  const required: Array<[unknown, string]> = [
    [config?.server?.resource_id, "server.resource_id"],
    [config?.server?.listen, "server.listen"],
    [config?.identity?.issuer, "identity.issuer"],
    [config?.identity?.jwks_uri, "identity.jwks_uri"],
    [config?.identity?.agent_id_claim, "identity.agent_id_claim"],
    [config?.identity?.required_audience, "identity.required_audience"],
    [config?.policy?.source, "policy.source"],
  ];

  // Conditional requirements
  if (config?.step_up?.mode === "webhook") {
    required.push([config?.step_up?.webhook_url, "step_up.webhook_url"]);
  }
  if (config?.audit?.sink === "file") {
    required.push([config?.audit?.path, "audit.path"]);
  }
  if (config.upstream !== undefined) {
    required.push([config.upstream.command, "upstream.command"]);
  }

  for (const [value, name] of required) {
    if (!value) {
      throw new Error(`limekey config missing required field: ${name}`);
    }
  }

  // Validate listen address format
  try {
    const addr = parseListenAddress(config.server.listen);
    if (isNaN(addr.port) || addr.port < 1 || addr.port > 65535) {
      throw new Error("port out of range");
    }
  } catch {
    throw new Error(
      `invalid server.listen: "${config.server.listen}" — expected "host:port" with port 1-65535`,
    );
  }

  // Validate timeout
  if (
    typeof config.step_up.timeout_seconds !== "number" ||
    config.step_up.timeout_seconds <= 0
  ) {
    throw new Error(
      `step_up.timeout_seconds must be a positive number, got: ${config.step_up.timeout_seconds}`,
    );
  }
}
