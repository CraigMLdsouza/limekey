#!/bin/sh
set -e

# If the command argument is 'mcp', start the MCP server
if [ "$1" = "mcp" ]; then
  exec node dist/mcp.js
fi

# Default to starting the HTTP gateway server
exec node dist/index.js "$@"
