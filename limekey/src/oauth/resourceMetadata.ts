/**
 * RFC 9728 — OAuth 2.0 Protected Resource Metadata.
 *
 * Limekey exposes this so MCP clients can auto-discover which
 * authorization server to get a token from before calling a protected
 * MCP server sitting behind Limekey.
 */

export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers: string[];
  bearer_methods_supported: string[];
  resource_documentation?: string;
}

export function buildResourceMetadata(opts: {
  resourceId: string;
  authorizationServerIssuer: string;
  docsUrl?: string;
}): ProtectedResourceMetadata {
  return {
    resource: opts.resourceId,
    authorization_servers: [opts.authorizationServerIssuer],
    bearer_methods_supported: ["header"],
    resource_documentation: opts.docsUrl,
  };
}

/**
 * Fastify route handler for GET /.well-known/oauth-protected-resource
 */
export async function resourceMetadataHandler(
  metadata: ProtectedResourceMetadata,
) {
  return metadata;
}
