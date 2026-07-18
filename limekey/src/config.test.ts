import { describe, it, expect, afterEach } from "vitest";
import { loadConfig, parseListenAddress } from "./config.js";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import yaml from "js-yaml";

/**
 * Helper: create a temporary directory that is cleaned up after each test.
 */
function makeTmpDir(): string {
  const dir = join(tmpdir(), `limekey-config-test-${randomUUID()}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

/**
 * Helper: write a YAML config file from a plain object.
 */
function writeYaml(dir: string, obj: Record<string, unknown>): string {
  const filePath = join(dir, "config.yaml");
  writeFileSync(filePath, yaml.dump(obj), "utf-8");
  return filePath;
}

/**
 * A minimal valid config object that passes all validation.
 * Tests can spread this and override specific fields.
 */
function validConfigObj(): Record<string, unknown> {
  return {
    server: { resource_id: "my-resource", listen: "0.0.0.0:8443" },
    identity: {
      issuer: "https://idp.example.com",
      jwks_uri: "https://idp.example.com/.well-known/jwks.json",
      required_audience: "https://api.example.com",
    },
    policy: { source: "./policies" },
    step_up: { webhook_url: "https://hook.example.com/approve" },
    audit: { path: "/var/log/limekey/audit.log" },
  };
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe("loadConfig", () => {
  let tmpDir: string;

  afterEach(() => {
    if (tmpDir) {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // 1. Loads a valid YAML config and returns the parsed result
  it("loads a valid YAML config file and returns the parsed config", () => {
    tmpDir = makeTmpDir();
    const filePath = writeYaml(tmpDir, validConfigObj());
    const config = loadConfig(filePath);

    expect(config.server.resource_id).toBe("my-resource");
    expect(config.server.listen).toBe("0.0.0.0:8443");
    expect(config.identity.issuer).toBe("https://idp.example.com");
    expect(config.identity.jwks_uri).toBe(
      "https://idp.example.com/.well-known/jwks.json",
    );
    expect(config.identity.required_audience).toBe(
      "https://api.example.com",
    );
    expect(config.policy.source).toBe("./policies");
    expect(config.step_up.webhook_url).toBe(
      "https://hook.example.com/approve",
    );
    expect(config.audit.path).toBe("/var/log/limekey/audit.log");
  });

  // 2. Throws on each missing required field
  describe("throws on missing required fields", () => {
    const requiredFieldCases: Array<{
      description: string;
      modify: (obj: Record<string, unknown>) => void;
      expectedMessage: string;
    }> = [
      {
        description: "server.resource_id",
        modify: (obj) => {
          (obj.server as Record<string, unknown>).resource_id = undefined;
        },
        expectedMessage: "server.resource_id",
      },
      {
        description: "identity.issuer",
        modify: (obj) => {
          (obj.identity as Record<string, unknown>).issuer = undefined;
        },
        expectedMessage: "identity.issuer",
      },
      {
        description: "identity.jwks_uri",
        modify: (obj) => {
          (obj.identity as Record<string, unknown>).jwks_uri = undefined;
        },
        expectedMessage: "identity.jwks_uri",
      },
      {
        description: "identity.required_audience",
        modify: (obj) => {
          (obj.identity as Record<string, unknown>).required_audience =
            undefined;
        },
        expectedMessage: "identity.required_audience",
      },
      {
        description: "policy.source",
        modify: (obj) => {
          (obj.policy as Record<string, unknown>).source = undefined;
        },
        expectedMessage: "policy.source",
      },
    ];

    for (const { description, modify, expectedMessage } of requiredFieldCases) {
      it(`missing ${description}`, () => {
        tmpDir = makeTmpDir();
        const obj = validConfigObj();
        modify(obj);
        const filePath = writeYaml(tmpDir, obj);

        expect(() => loadConfig(filePath)).toThrowError(expectedMessage);
      });
    }
  });

  // 3. Applies defaults for omitted optional fields
  it("applies defaults when optional fields are omitted", () => {
    tmpDir = makeTmpDir();
    // Provide only the required fields; omit everything that has defaults.
    const minimal: Record<string, unknown> = {
      server: { resource_id: "res-1" },
      identity: {
        issuer: "https://idp.example.com",
        jwks_uri: "https://idp.example.com/.well-known/jwks.json",
        required_audience: "https://api.example.com",
      },
      policy: { source: "./policies" },
      // step_up.webhook_url is required when mode defaults to "webhook",
      // so we must supply it.
      step_up: { webhook_url: "https://hook.example.com/approve" },
      // audit.path is required when sink defaults to "file",
      // so we must supply it.
      audit: { path: "/tmp/audit.log" },
    };
    const filePath = writeYaml(tmpDir, minimal);
    const config = loadConfig(filePath);

    // server defaults
    expect(config.server.listen).toBe("0.0.0.0:8443");

    // identity defaults
    expect(config.identity.provider).toBe("generic_oidc");
    expect(config.identity.agent_id_claim).toBe("agent_id");

    // policy defaults
    expect(config.policy.engine).toBe("yaml");
    expect(config.policy.default).toBe("deny");

    // step_up defaults
    expect(config.step_up.mode).toBe("webhook");
    expect(config.step_up.timeout_seconds).toBe(120);
    expect(config.step_up.on_timeout).toBe("deny");

    // audit defaults
    expect(config.audit.sink).toBe("file");
  });

  // 4. step_up.webhook_url is required when mode is "webhook"
  it("throws when step_up.mode is webhook but webhook_url is missing", () => {
    tmpDir = makeTmpDir();
    const obj = validConfigObj();
    (obj.step_up as Record<string, unknown>).mode = "webhook";
    delete (obj.step_up as Record<string, unknown>).webhook_url;
    const filePath = writeYaml(tmpDir, obj);

    expect(() => loadConfig(filePath)).toThrowError("step_up.webhook_url");
  });

  it("does not throw when step_up.mode is ciba and webhook_url is missing", () => {
    tmpDir = makeTmpDir();
    const obj = validConfigObj();
    (obj.step_up as Record<string, unknown>).mode = "ciba";
    delete (obj.step_up as Record<string, unknown>).webhook_url;
    const filePath = writeYaml(tmpDir, obj);

    // Should not throw — webhook_url is not required for ciba mode
    expect(() => loadConfig(filePath)).not.toThrow();
  });

  // 5. audit.path is required when sink is "file"
  it("throws when audit.sink is file but path is missing", () => {
    tmpDir = makeTmpDir();
    const obj = validConfigObj();
    (obj.audit as Record<string, unknown>).sink = "file";
    delete (obj.audit as Record<string, unknown>).path;
    const filePath = writeYaml(tmpDir, obj);

    expect(() => loadConfig(filePath)).toThrowError("audit.path");
  });

  it("does not throw when audit.sink is http and path is missing", () => {
    tmpDir = makeTmpDir();
    const obj = validConfigObj();
    (obj.audit as Record<string, unknown>).sink = "http";
    delete (obj.audit as Record<string, unknown>).path;
    const filePath = writeYaml(tmpDir, obj);

    expect(() => loadConfig(filePath)).not.toThrow();
  });

  // 10. Validates port range (1-65535)
  describe("validates port range", () => {
    it("throws when port is 0", () => {
      tmpDir = makeTmpDir();
      const obj = validConfigObj();
      (obj.server as Record<string, unknown>).listen = "0.0.0.0:0";
      const filePath = writeYaml(tmpDir, obj);

      expect(() => loadConfig(filePath)).toThrowError("server.listen");
    });

    it("throws when port exceeds 65535", () => {
      tmpDir = makeTmpDir();
      const obj = validConfigObj();
      (obj.server as Record<string, unknown>).listen = "0.0.0.0:70000";
      const filePath = writeYaml(tmpDir, obj);

      expect(() => loadConfig(filePath)).toThrowError("server.listen");
    });

    it("throws when port is negative", () => {
      tmpDir = makeTmpDir();
      const obj = validConfigObj();
      (obj.server as Record<string, unknown>).listen = "0.0.0.0:-1";
      const filePath = writeYaml(tmpDir, obj);

      expect(() => loadConfig(filePath)).toThrowError("server.listen");
    });

    it("accepts port 1 (minimum)", () => {
      tmpDir = makeTmpDir();
      const obj = validConfigObj();
      (obj.server as Record<string, unknown>).listen = "0.0.0.0:1";
      const filePath = writeYaml(tmpDir, obj);

      expect(() => loadConfig(filePath)).not.toThrow();
    });

    it("accepts port 65535 (maximum)", () => {
      tmpDir = makeTmpDir();
      const obj = validConfigObj();
      (obj.server as Record<string, unknown>).listen = "0.0.0.0:65535";
      const filePath = writeYaml(tmpDir, obj);

      expect(() => loadConfig(filePath)).not.toThrow();
    });
  });

  // 11. Throws on missing file
  it("throws when the config file does not exist", () => {
    const nonExistentPath = join(
      tmpdir(),
      `limekey-missing-${randomUUID()}`,
      "does-not-exist.yaml",
    );
    expect(() => loadConfig(nonExistentPath)).toThrow();
  });
});

// ─── parseListenAddress ─────────────────────────────────────────────────────

describe("parseListenAddress", () => {
  // 6. Parses 'host:port' correctly
  it("parses 'host:port' correctly", () => {
    const addr = parseListenAddress("0.0.0.0:8443");
    expect(addr.host).toBe("0.0.0.0");
    expect(addr.port).toBe(8443);
  });

  it("parses '127.0.0.1:3000' correctly", () => {
    const addr = parseListenAddress("127.0.0.1:3000");
    expect(addr.host).toBe("127.0.0.1");
    expect(addr.port).toBe(3000);
  });

  it("parses 'localhost:443' correctly", () => {
    const addr = parseListenAddress("localhost:443");
    expect(addr.host).toBe("localhost");
    expect(addr.port).toBe(443);
  });

  // 7. Handles ':port' with default host
  it("handles ':port' with default host 0.0.0.0", () => {
    const addr = parseListenAddress(":8443");
    expect(addr.host).toBe("0.0.0.0");
    expect(addr.port).toBe(8443);
  });

  // 8. Handles port-only input
  it("handles port-only string input", () => {
    const addr = parseListenAddress("8443");
    expect(addr.host).toBe("0.0.0.0");
    expect(addr.port).toBe(8443);
  });

  it("handles port-only string '443'", () => {
    const addr = parseListenAddress("443");
    expect(addr.host).toBe("0.0.0.0");
    expect(addr.port).toBe(443);
  });

  // 9. Throws on invalid format
  it("throws on completely invalid format", () => {
    expect(() => parseListenAddress("a:b:c")).toThrowError(
      "invalid server.listen format",
    );
  });

  it("throws on non-numeric single value", () => {
    expect(() => parseListenAddress("notanumber")).toThrowError(
      "invalid server.listen format",
    );
  });

  it("throws on empty string", () => {
    expect(() => parseListenAddress("")).toThrowError(
      "invalid server.listen format",
    );
  });
});
