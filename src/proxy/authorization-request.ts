import { randomUUID } from "node:crypto";
import type { AuthorizationRequest } from "../types/authorization.js";

/**
 * Construct a canonical AuthorizationRequest from validated token claims and
 * tool call data. This is the single normalization point shared by all entry
 * points (HTTP, MCP proxy, future SDK).
 *
 * @param agentId    Value of the configured agent_id_claim in the JWT.
 * @param sub        JWT sub claim (human user identity).
 * @param toolName   The tool being authorized.
 * @param toolArgs   The arguments payload for the tool call.
 * @param sessionId  Optional session identifier for tracking.
 */
export function buildAuthorizationRequest(
  agentId: string,
  sub: string,
  toolName: string,
  toolArgs: Record<string, unknown>,
  sessionId?: string,
): AuthorizationRequest {
  return {
    requestId: randomUUID(),
    timestamp: new Date().toISOString(),
    principal: {
      agentId,
      sub,
    },
    tool: toolName,
    arguments: toolArgs,
    context: {
      sessionId,
    },
  };
}
