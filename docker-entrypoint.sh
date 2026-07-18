#!/bin/sh
set -e

if [ "$1" = "mcp" ]; then
    shift
    exec node dist/mcp.js "$@"
fi

if [ "$1" = "server" ] || [ -z "$1" ]; then
    [ "$1" = "server" ] && shift
    exec node dist/index.js "$@"
fi

exec "$@"