#!/usr/bin/env bash
# facilitator-healthcheck.sh — standalone probe for egg-verify's deep health check.
# Hits GET /healthz and exits 0 when "ok", 1 when "degraded" or unreachable,
# so watchers and crons can key off the exit code.
#
# usage: ./scripts/facilitator-healthcheck.sh [base-url]
#   default base: https://egg-verify.onrender.com
#   env override: EGG_VERIFY_BASE
set -u
BASE="${1:-${EGG_VERIFY_BASE:-https://egg-verify.onrender.com}}"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

code="$(curl -sS -o "$TMP" -w '%{http_code}' --max-time 90 \
  -A 'egg-verify-healthcheck/1.0' "$BASE/healthz" 2>/dev/null || echo "000")"

status="$(python3 -c "import json,sys; print(json.load(open('$TMP')).get('status','?'))" 2>/dev/null || echo "?")"

if [ "$code" = "200" ] && [ "$status" = "ok" ]; then
  echo "OK ($BASE/healthz, HTTP $code, status=$status)"
  exit 0
else
  echo "DEGRADED ($BASE/healthz, HTTP $code, status=$status)"
  head -c 2000 "$TMP"; echo
  exit 1
fi
