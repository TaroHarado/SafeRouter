#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-./cape}"

echo "== cape smoke (posix) =="
"$BIN" --help >/dev/null
echo "help: ok"

"$BIN" audit >/dev/null
echo "audit: ok"

"$BIN" registry list >/dev/null
echo "registry: ok"

"$BIN" score --help >/dev/null
echo "score: ok"

echo "smoke: ok"
