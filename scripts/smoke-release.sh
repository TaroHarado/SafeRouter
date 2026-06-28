#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-./cape}"

echo "== cape smoke (posix) =="
"$BIN" --help >/dev/null
echo "help: ok"

"$BIN" audit >/dev/null
echo "audit: ok"

"$BIN" sentinel --interval 5ms >/dev/null
echo "sentinel: ok"

echo "smoke: ok"
