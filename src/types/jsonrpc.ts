/**
 * JSON-RPC 2.0 typed message shapes used by the proxy layer.
 *
 * Kept intentionally narrow: only the fields Limekey needs to read or write.
 * Unknown fields in upstream messages are preserved by passing raw strings
 * through and only parsing where interception is required.
 */

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: number | string | null;
  method: string;
  params?: unknown;
}

export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: number | string | null;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}
