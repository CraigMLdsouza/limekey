import { describe, it, expect } from "vitest";
import {
  buildResourceMetadata,
  resourceMetadataHandler,
  type ProtectedResourceMetadata,
} from "./resourceMetadata.js";

describe("buildResourceMetadata", () => {
  const baseOpts = {
    resourceId: "https://mcp.example.com",
    authorizationServerIssuer: "https://auth.example.com",
  };

  it("returns an object with all required fields", () => {
    const meta = buildResourceMetadata(baseOpts);

    expect(meta).toHaveProperty("resource");
    expect(meta).toHaveProperty("authorization_servers");
    expect(meta).toHaveProperty("bearer_methods_supported");
  });

  it("sets 'resource' to the provided resourceId", () => {
    const meta = buildResourceMetadata(baseOpts);

    expect(meta.resource).toBe("https://mcp.example.com");
  });

  it("puts the authorization server issuer in the 'authorization_servers' array", () => {
    const meta = buildResourceMetadata(baseOpts);

    expect(meta.authorization_servers).toEqual(["https://auth.example.com"]);
  });

  it("sets bearer_methods_supported to ['header']", () => {
    const meta = buildResourceMetadata(baseOpts);

    expect(meta.bearer_methods_supported).toEqual(["header"]);
  });

  it("includes resource_documentation when docsUrl is provided", () => {
    const meta = buildResourceMetadata({
      ...baseOpts,
      docsUrl: "https://docs.example.com/api",
    });

    expect(meta.resource_documentation).toBe("https://docs.example.com/api");
  });

  it("leaves resource_documentation undefined when docsUrl is omitted", () => {
    const meta = buildResourceMetadata(baseOpts);

    expect(meta.resource_documentation).toBeUndefined();
  });
});

describe("resourceMetadataHandler", () => {
  it("returns the metadata object as-is", async () => {
    const metadata: ProtectedResourceMetadata = {
      resource: "https://mcp.example.com",
      authorization_servers: ["https://auth.example.com"],
      bearer_methods_supported: ["header"],
      resource_documentation: "https://docs.example.com",
    };

    const result = await resourceMetadataHandler(metadata);

    expect(result).toBe(metadata);
  });
});
