#!/bin/sh
# M6 hero-smoke fixture: a fictional stdio MCP server, plain sh, no network.
# One read tool and one write tool; the write tool only exists to prove that a
# widened allowlist waits for a second approval. Every tools/call line is
# appended to $TMPDIR/m6-calls.log, the private temp dir the kernel's Seatbelt
# sandbox gives this child, so the smoke can read what the server really saw.
set -eu

dir="${TMPDIR:-/tmp}"
echo "$$" >"$dir/m6-pid"

while IFS= read -r line; do
  id="$(printf '%s\n' "$line" | /usr/bin/sed -n 's/.*"id"[ ]*:[ ]*\([0-9][0-9]*\).*/\1/p')"
  case "$line" in
    *'"method":"initialize"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"m6-fixture","version":"1"}}}\n' "$id"
      ;;
    *'"method":"tools/list"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"READ_NOTE","description":"Read a fictional note.","inputSchema":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}},{"name":"WRITE_NOTE","description":"Write a fictional note.","inputSchema":{"type":"object","properties":{"note":{"type":"string"}},"required":["note"]}}],"nextCursor":null}}\n' "$id"
      ;;
    *'"method":"tools/call"'*)
      printf '%s\n' "$line" >>"$dir/m6-calls.log"
      printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"m6 fixture ok"}],"isError":false}}\n' "$id"
      ;;
  esac
done
