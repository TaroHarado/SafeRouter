#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${1:-$ROOT/target/debug/cape}"
PORT="${2:-8484}"

cleanup() {
  if [[ -n "${WEB_PID:-}" ]]; then
    kill "$WEB_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "== SafeRouter local smoke =="
"$BIN" web --listen "127.0.0.1:${PORT}" --site "$ROOT/site" >/tmp/saferouter-web.log 2>&1 &
WEB_PID=$!

for _ in {1..50}; do
  if curl -fsS "http://127.0.0.1:${PORT}/api/health" >/dev/null; then
    break
  fi
  sleep 0.2
done

curl -fsS "http://127.0.0.1:${PORT}/api/health" >/dev/null
echo "health: ok"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "content-type: application/json" \
  -d '{"base_url":""}' \
  "http://127.0.0.1:${PORT}/api/score")

if [[ "$STATUS" != "400" ]]; then
  echo "expected /api/score invalid request to return 400, got $STATUS"
  exit 1
fi
echo "invalid score request: ok"

SESSION_JSON=$(curl -fsS \
  -H "content-type: application/json" \
  -d '{"task":"Smoke test session"}' \
  "http://127.0.0.1:${PORT}/api/session/init")

SESSION_ID=$(printf '%s' "$SESSION_JSON" | sed -n 's/.*"session_id":"\([^"]*\)".*/\1/p')
if [[ -z "$SESSION_ID" ]]; then
  echo "session init did not return session_id"
  exit 1
fi
echo "session init: ok"

POLICY_JSON=$(curl -fsS \
  -H "content-type: application/json" \
  -d "{\"session_id\":\"$SESSION_ID\",\"action_kind\":\"file-read\",\"target\":\".env\",\"provider_risk\":\"high\"}" \
  "http://127.0.0.1:${PORT}/api/policy/evaluate")

printf '%s' "$POLICY_JSON" | grep -q 'Ask\|Block\|AllowWithRedaction'
echo "policy evaluate: ok"

curl -fsS "http://127.0.0.1:${PORT}/" >/dev/null
echo "site: ok"

echo "smoke-local: ok"
