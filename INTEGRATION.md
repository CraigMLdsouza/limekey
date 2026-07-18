# Limekey Agent Integration Guide

This guide explains how to connect your AI Agent application (built using LangChain, LlamaIndex, CrewAI, AutoGen, or raw MCP clients) to the Limekey Authorization Gateway to secure tool execution.

---

## The Integration Flow

Limekey operates as an out-of-process **authorization proxy**. Instead of letting the LLM execute tools directly, the agent client queries Limekey before executing any tool.

```
[ AI Agent Code ] 
       │
       ├─► 1. Query: POST /v0/authorize (Bearer JWT + Tool + Args)
       │
       ▼
  [ LIMEKEY ]
       │
       ├─► 2. Evaluates YAML Policy (Allow / Deny / Step-up)
       │
       ▼
[ Decision Response ]
       │
       ├─► HTTP 200 OK (Allow) ──────► 3. Call Actual Tool / MCP Server
       │
       └─► HTTP 403 Forbidden ────────► 3. Halt & inform human
```

---

## Step 1: Token Setup

When you authenticate the human user in your agent application, configure your Identity Provider (e.g. Auth0, WorkOS) to include the `agent_id` custom claim on the access token. 

The access token JWT payload should look like this:
```json
{
  "sub": "usr_98372",                          "//": "The human principal",
  "agent_id": "support-agent-prod",            "//": "The explicit agent identity",
  "aud": "https://api.acme.com/mcp",           "//": "Limekey resource indicator",
  "iss": "https://auth.acme.com/",
  "exp": 1784306209
}
```

---

## Step 2: Implementation Examples

Wrap the tool execution block in your agent application code using the code templates below.

### Python Example

```python
import requests
import sys

LIMEKEY_URL = "http://localhost:8443/v0/authorize"

def call_tool_secured(user_token: str, tool_name: str, tool_args: dict):
    """
    Wraps tool execution with a Limekey authorization check.
    """
    headers = {
        "Authorization": f"Bearer {user_token}",
        "Content-Type": "application/json"
    }
    payload = {
        "tool_name": tool_name,
        "arguments": tool_args,
        "session_id": "optional-session-id-123"
    }

    try:
        # Query Limekey decision point
        response = requests.post(LIMEKEY_URL, json=payload, headers=headers)
        
        if response.status_code == 200:
            # ALLOW: Proceed to run the tool
            print(f"✅ Authorization granted for tool '{tool_name}'")
            return execute_actual_tool(tool_name, tool_args)
            
        elif response.status_code == 403:
            # DENY: Blocked by YAML policy
            rule = response.json().get("rule", "default")
            print(f"❌ Authorization denied by policy rule: '{rule}'")
            raise PermissionError(f"Action blocked by policy: '{rule}'")
            
        elif response.status_code == 401:
            # UNAUTHORIZED: Token validation failed
            raise PermissionError("Access token is invalid or expired.")
            
        else:
            raise RuntimeError(f"Unexpected Limekey status: {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        # Fallback to fail-closed on network errors to ensure security
        print(f"⚠️ Security Gateway unreachable: {e}")
        raise PermissionError("Authorization check failed: Gateway unreachable.")

def execute_actual_tool(name, args):
    # Place your actual tool call execution logic here (e.g. database write, Slack post)
    return {"status": "success", "result": "Action executed"}
```

### Node.js / TypeScript Example

```typescript
import { request } from "undici";

const LIMEKEY_URL = "http://localhost:8443/v0/authorize";

interface AuthorizeResponse {
  decision: "allow" | "deny";
  rule?: string;
}

async function callToolSecured(
  userToken: string,
  toolName: string,
  toolArgs: Record<string, unknown>
): Promise<unknown> {
  try {
    const { statusCode, body } = await request(LIMEKEY_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${userToken}`,
      },
      body: JSON.stringify({
        tool_name: toolName,
        arguments: toolArgs,
      }),
    });

    if (statusCode === 200) {
      console.log(`✅ Authorization granted for tool '${toolName}'`);
      return executeActualTool(toolName, toolArgs);
    }

    if (statusCode === 403) {
      const resData = (await body.json()) as AuthorizeResponse;
      throw new Error(`Action blocked by policy rule: '${resData.rule}'`);
    }

    throw new Error(`Authorization check failed with status: ${statusCode}`);
  } catch (err) {
    // Fail-closed on authorization gateway errors
    console.error("⚠️ Security Gate block:", err);
    throw err;
  }
}

async function executeActualTool(name: string, args: any) {
  return { status: "success" };
}
```

---

## Step 3: Handle Security Rejections in the LLM

When Limekey blocks a tool call, raise a permission error in your code. Pass a clear, helpful message back to the LLM so it can handle the rejection dynamically:

```
User: "Can you delete database table users?"
Agent: "Analyzing request..."
[Limekey check fails: db.delete is blocked by policy 'block ledger writes']
Agent: "I apologize, but I am blocked by your team's security policy from deleting database tables."
```

This prevents the agent from hanging, looping, or attempting to bypass restrictions.

---

## Alternative: Transparent MCP Policy Enforcement Proxy

If your agent communicates with tools via the **Model Context Protocol (MCP)**, you do not need to modify any application code or call authorization APIs manually. 

Instead, configure the Limekey MCP server to act as a **transparent policy enforcement proxy** by specifying the `upstream` server in your `limekey.config.yaml`.

```
[ Cursor / Claude Desktop ]
            │
            ▼ (tools/call)
   [ Limekey Proxy ]  ── (Denied: Native MCP tool error returned)
            │
            ▼ (Allowed: Forwarded)
  [ Upstream MCP Server ]
```

When Limekey blocks a tool call, it returns a standard MCP tool execution error containing:
- A fixed error message: `"Operation denied by LimeKey policy."`
- The `request_id` for tracking.

The client application (such as Cursor or Claude Desktop) natively renders this as a tool execution failure, preventing the agent from executing the command or bypassing the gateway.

