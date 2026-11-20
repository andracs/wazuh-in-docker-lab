#!/usr/bin/env bash
# ==============================================================================
# Wazuh Security Lab - quick smoke test (requires Docker).
#
# Validates that the Compose file is accepted, the endpoint image builds and
# that the stack comes up with 8 healthy containers and 5 active agents.
# For the full 18-point checklist run tests/integration_check.sh.
# ==============================================================================
set -uo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_DIR}"

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[1;31mFAIL\033[0m %s\n' "$*"; }
skip() { SKIP=$((SKIP+1)); printf '  \033[1;33mSKIP\033[0m %s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon not reachable - cannot run the smoke test."
  exit 2
fi

step "1. docker compose config validates"
if docker compose config >/dev/null 2>&1; then ok "compose config"; else bad "compose config"; fi

step "2. endpoint image builds"
if docker compose build; then ok "endpoint image build"; else bad "endpoint image build"; exit 1; fi

step "3. all eight containers start and become healthy"
if ! ./lab.sh up; then
  bad "lab.sh up"
  exit 1
fi
for c in wazuh-manager wazuh-indexer wazuh-dashboard web-safe db-safe legacy-web web-attack client-01; do
  state=$(docker inspect -f '{{.State.Health.Status}}' "$c" 2>/dev/null || echo "missing")
  if [ "$state" = "healthy" ]; then ok "container $c healthy"; else bad "container $c ($state)"; fi
done

step "4. five distinct agents registered and connected"
COUNT=$(docker exec wazuh-manager sh -c \
  "curl -sk -u 'wazuh-wui:MyS3cr37P450r.*-' 'https://localhost:55000/agents?agents_list=list'" \
  | python3 -c \
  'import json,sys;
try:
    d=json.load(sys.stdin)
    a=[x for x in d["data"]["affected_items"] if x["id"]!="000"]
    print(sum(1 for x in a if x["status"]=="active"))
except Exception:
    print(0)')
if [ "${COUNT:-0}" -eq 5 ]; then
  ok "5 active agents"
else
  bad "expected 5 active agents, got ${COUNT:-0}"
fi

echo
echo "Smoke test result: PASS=${PASS} FAIL=${FAIL} SKIP=${SKIP}"
[ "${FAIL}" -eq 0 ]
