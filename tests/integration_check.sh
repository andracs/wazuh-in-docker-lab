#!/usr/bin/env bash
# ==============================================================================
# Wazuh Security Lab - integration verification (REQUIRES a running lab).
#
# Implements the QA checklist that needs a live Wazuh stack
# (see README "Test og verifikation"). Each check prints PASS/FAIL/SKIP.
#
#   Usage:  ./lab.sh up && ./lab.sh verify
#
# Checks against the REAL Wazuh components (API, indexer), not just log files.
# ==============================================================================
set -uo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_DIR}"
[ -f .env ] && { set -a; . ./.env; set +a; }

API_USER="${API_USER:-wazuh-wui}"
API_PASS="${API_PASSWORD:-MyS3cr37P450r.*-}"
IDX_USER="${INDEXER_USERNAME:-admin}"
IDX_PASS="${INDEXER_PASSWORD:-SecretPassword}"
MAL_RULES='"100110","100111","100112","100113","100115","100122","100123","100130","100140","100141"'
EP="web-safe db-safe legacy-web web-attack client-01"

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); printf '\033[1;32m[PASS]\033[0m %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '\033[1;31m[FAIL]\033[0m %s\n' "$*"; }
skip() { SKIP=$((SKIP+1)); printf '\033[1;33m[SKIP]\033[0m %s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon not reachable - integration checks skipped." >&2
  exit 2
fi
if ! docker compose ps 2>/dev/null | grep -q wazuh; then
  echo "The lab does not appear to be running. Start it with: ./lab.sh up" >&2
  exit 2
fi

# --- helpers ------------------------------------------------------------------
api()   { docker exec wazuh-manager sh -c "curl -sk -u '${API_USER}:${API_PASS}' $*"; }
idx()   { docker exec wazuh-manager sh -c "curl -sk -u '${IDX_USER}:${IDX_PASS}' $*"; }
attr()  { api "'https://localhost:55000/agents?agents_list=list'" | FILTER="$1" python3 -c '
import json,sys,os
try:
    d=json.load(sys.stdin); items=d["data"]["affected_items"]; items=[a for a in items if a["id"]!="000"]
    print(os.environ["FILTER"](items))
except Exception as exc:
    print("ERROR:"+str(exc))
'; }
alerts_query() {  # $1: Lucene query, $2: index pattern (default wazuh-alerts)
  idx "-X POST 'https://wazuh.indexer:9200/${2:-wazuh-alerts-*}/_search?size=10000' \
      -H 'Content-Type: application/json' -d '{\"query\":{\"query_string\":{\"query\":\"$1\"}}}'" \
      | python3 -c '
import json,sys
try:
    d=json.load(sys.stdin); print(d["hits"]["total"]["value"])
except Exception as exc:
    print("ERROR:"+str(exc))'; }
alert_ids() {  # print the distinct wazuh rule ids delivered today
  idx "-X POST 'https://wazuh.indexer:9200/wazuh-alerts-*/_search?size=0' \
      -H 'Content-Type: application/json' -d '{\"aggs\":{\"ids\":{\"terms\":{\"field\":\"rule.id\",\"size\":1000}}}}'" \
      | python3 -c '
import json,sys
try:
    d=json.load(sys.stdin)
    print(" ".join(b["key"] for b in d["aggregations"]["ids"]["buckets"]))
except Exception as exc:
    print("ERROR:"+str(exc))'; }
sca_of() {  # $1 agent id, prints "pass fail"
  api "'https://localhost:55000/sca/$1/checks/security_lab_baseline'" \
   | CHECKID="$2" python3 -c '
import json,sys,os
try:
    d=json.load(sys.stdin)
    items=d["data"]["affected_items"]
    if os.environ.get("CHECKID"):
        want=int(os.environ["CHECKID"])
        c=[x for x in items if x.get("id")==want]
        print(c[0]["result"] if c else "missing")
    else:
        res=[i.get("result") for i in items]
        print(sum(1 for r in res if r=="passed"), sum(1 for r in res if r=="failed"))
except Exception as exc:
    print("ERROR:"+str(exc))'; }
agent_id_by_name() {
  attr "lambda a: (next((x[\"id\"] for x in a if x[\"name\"]==\"$1\"), \"none\"))"; }
wait_sca() {  # $1 agent id - wait for scan after a restart (scan_on_start)
  for _ in $(seq 1 60); do
    R=$(sca_of "$1") || true
    case "$R" in ERROR*) sleep 5 ;; *) [ -n "$R" ] && return 0 ;; esac
    sleep 5
  done
  return 0; }

# ==============================================================================
step "1. Docker Compose configuration validates"
if docker compose config >/dev/null 2>&1; then ok "docker compose config"; else bad "docker compose config"; fi

step "2. Endpoint Docker images build"
if docker compose build; then ok "endpoint image build"; else bad "endpoint image build"; fi

step "3. All eight containers are running"
RUNNING=$(docker compose ps --format json 2>/dev/null | python3 -c '
import json,sys
try:
    items=json.load(sys.stdin)
    if isinstance(items, dict): items=[items]
    print(sum(1 for c in items if (c.get("State") or c.get("state"))=="running"))
except Exception: print(0)')
[ "${RUNNING:-0}" -eq 8 ] && ok "8 running containers" || bad "expected 8 running containers, got ${RUNNING:-0}"

step "4. Wazuh infrastructure healthy"
HEALTHY=$(docker compose ps --format json 2>/dev/null | python3 -c '
import json,sys
try:
    items=json.load(sys.stdin)
    if isinstance(items, dict): items=[items]
    names=("wazuh-manager","wazuh-indexer","wazuh-dashboard")
    print(sum(1 for c in items if c.get("Service") in names and (c.get("Health") or c.get("health"))=="healthy"))
except Exception: print(0)')
[ "${HEALTHY:-0}" -eq 3 ] && ok "manager/indexer/dashboard healthy" || bad "infrastructure health: ${HEALTHY:-0}/3"

step "5. Five distinct agents are registered"
N=$(attr "len") || N="ERROR"
COUNT_OK=false; [ "${N:-0}" -eq 5 ] && COUNT_OK=true
$COUNT_OK && ok "5 agents registered" || bad "agents: got '${N:-0}', expected 5"
NAMES=$(attr "\" \".join(sorted(x[\"name\"] for x in a))" || true)
if [ "${NAMES}" = "client-01 db-safe legacy-web web-attack web-safe" ]; then
  ok "expected agent names"
else
  bad "unexpected agent names: ${NAMES}"
fi

step "6. All five agents report active status"
ACTIVE=$(attr "sum(1 for x in a if x[\"status\"]==\"active\")" || echo 0)
[ "${ACTIVE:-0}" -eq 5 ] && ok "5 active agents" || bad "active agents: ${ACTIVE:-0}/5"

step "7. JSON events are ingested by Wazuh (querying the indexer)"
# level-0 events are not indexed, so verify that lab rules have produced
# alerts after scenarios ran (rule group "security_lab"):
N=$(alerts_query 'rule.groups:security_lab') || N=ERROR
if [ "${N:-0}" -gt 0 ] 2>/dev/null; then
  ok "lab rules active, ${N} matching alerts indexed"
else
  # not an error per se: no scenario has run yet
  skip "no lab alerts yet (run a scenario first)"
fi

step "8. Compliant endpoints pass their lab SCA checks (10100-10104)"
for ep in web-safe db-safe client-01; do
  AID=$(agent_id_by_name "$ep")
  R=$(sca_of "$AID")
  case "$R" in
    "5 0") ok "$ep: 5/5 SCA checks passed" ;;
    ERROR*|"") bad "$ep: SCA result unavailable ($R)" ;;
    *) bad "$ep: expected 5 passes, got '$R'" ;;
  esac
done

step "9. legacy-web fails its three intended SCA checks"
AID=$(agent_id_by_name legacy-web)
R=$(sca_of "$AID")
case "$R" in
  "2 3") ok "legacy-web: 2 passed / 3 failed (intended)" ;;
  ERROR*|"") bad "legacy-web: SCA result unavailable ($R)" ;;
  *) bad "legacy-web: expected '2 3', got '$R'" ;;
esac
for CHECK in 10100 10101 10102; do
  [ "$(sca_of "$AID" $CHECK)" = "failed" ] && ok "check id $CHECK failed (intended)" || bad "check id $CHECK"
done

step "10. File modification triggers a FIM alert"
./lab.sh scenario misconfiguration >/dev/null 2>&1
echo "   waiting up to 90s for the FIM alert to be indexed ..."
FIM=0
for _ in $(seq 1 18); do
  FIM=$(alerts_query 'rule.groups:syscheck AND syscheck.path:"/etc/labapp/app.conf"' || echo 0)
  [ "${FIM:-0}" -gt 0 ] 2>/dev/null && break
  sleep 5
done
[ "${FIM:-0}" -gt 0 ] 2>/dev/null && ok "FIM alert for app.conf present (${FIM})" \
  || bad "no FIM alert for /etc/labapp/app.conf"

step "11. Web attack events trigger the intended detection rules"
echo "   running scenario web-attack ..."; ./lab.sh scenario web-attack >/dev/null 2>&1
sleep 60
IDS=$(alert_ids) || IDS=""
for RID in 100110 100111 100112 100113 100115; do
  case " $IDS " in *" $RID "*)
      C=$(alerts_query "rule.id:$RID"); ok "rule $RID fired (${C:-?} alerts)" ;;
    *) bad "rule $RID did not fire" ;;
  esac
done

step "12. Client compromise events trigger the intended detection rules"
if [ "${ACTIVE:-0}" -eq 5 ]; then
  echo "   running scenario compromised-client ..."; ./lab.sh scenario compromised-client >/dev/null 2>&1
  sleep 60
  IDS=$(alert_ids) || IDS=""
  for RID in 100120 100122 100123 100130 100140 100141; do
    case " $IDS " in *" $RID "*)
        ok "rule $RID fired" ;;
      *) bad "rule $RID did not fire" ;;
    esac
  done
else
  skip "client-01 not active"
fi

step "13. Normal activity does NOT trigger the malicious-event rules"
BASE=$(alerts_query "data.endpoint:web-safe OR (data.endpoint:db-safe)")
echo "   running 60 normal events on web-safe only ..."
docker compose exec -T web-safe python3 /opt/lab/simulate.py normal --count 60 >/dev/null 2>&1
sleep 60
FALSE=$(idx "-X POST 'https://wazuh.indexer:9200/wazuh-alerts-*/_search?size=1' \
    -H 'Content-Type: application/json' -d '{\"query\":{\"query_string\":{\"query\":\"agent.name:web-safe AND rule.id:(${MAL_RULES})\"}}}'" \
    | python3 -c '
import json,sys
try:
    print(json.load(sys.stdin)["hits"]["total"]["value"])
except Exception:
    print("ERROR")')
[ "${FALSE:-ERROR}" = "0" ] && ok "no malicious-event alerts on web-safe (0)" || bad "web-safe produced malicious-rule alerts: ${FALSE:-?}"

step "14. Remediation changes the expected SCA result"
echo "   remediating legacy-web (debug=false, anonymous=false, chmod 640) ..."
docker compose exec -T legacy-web sh -c "
  sed -i 's/^debug=.*/debug=false/; s/^anonymous_access=.*/anonymous_access=false/' /etc/labapp/app.conf
  chmod 640 /etc/labapp/app.conf"
docker compose restart legacy-web >/dev/null 2>&1
AID=$(agent_id_by_name legacy-web)
echo "   waiting for scan-on-start SCA rescan ..."

wait_sca "$AID"
sleep 90
R=$(sca_of "$AID")
case "$R" in
  "5 0") ok "legacy-web now passes 5/5 after remediation" ;;
  *) bad "legacy-web SCA after remediation: '$R' (wait for the 30min interval if slower)" ;;
esac

step "15. Repeated scenario activation does not corrupt the environment"
FIRST=$(alerts_query 'rule.groups:security_lab')
./lab.sh scenario web-attack >/dev/null 2>&1
./lab.sh scenario web-attack >/dev/null 2>&1
sleep 60
SECOND=$(alerts_query 'rule.groups:security_lab')
if [ "${FIRST:-0}" -lt "${SECOND:-0}" ] 2>/dev/null; then
  ok "alerts increased after reactivation (${FIRST} -> ${SECOND}), stack still up"
else
  bad "alert volume did not grow on repeat (${FIRST} -> ${SECOND})"
fi
RUNNING=$(docker compose ps --format json 2>/dev/null | python3 -c '
import json,sys
try:
    items=json.load(sys.stdin)
    if isinstance(items, dict): items=[items]
    print(sum(1 for c in items if (c.get("State") or c.get("state"))=="running"))
except Exception: print(0)')
[ "${RUNNING:-0}" -eq 8 ] && ok "all 8 containers still running" || bad "containers after repeat: ${RUNNING:-0}/8"

step "16. The lab can be stopped and restarted"
BEFORE=$(attr "\" \".join(sorted(x[\"id\"] for x in a))" || echo none)
docker compose stop >/dev/null 2>&1
sleep 5
docker compose start >/dev/null 2>&1
sleep 90
ACTIVE2=$(attr "sum(1 for x in a if x[\"status\"]==\"active\")" || echo 0)
[ "${ACTIVE2:-0}" -eq 5 ] && ok "5 agents active again after stop/start" || bad "agents after restart: ${ACTIVE2:-0}/5"

step "17. Agent identities remain stable on restart"
AFTER=$(attr "\" \".join(sorted(x[\"id\"] for x in a))" || echo none)
if [ "$BEFORE" != "none" ] && [ "$BEFORE" = "$AFTER" ] && [ "$AFTER" != "none" ]; then
  ok "agent IDs unchanged (${AFTER})"
else
  bad "agent IDs changed: '$BEFORE' -> '$AFTER'"
fi

step "18. Documented student commands work"
CMDS=0
for c in "./lab.sh scenario normal" ; do
  if bash -c "$c" >/dev/null 2>&1; then CMDS=$((CMDS+1)); fi
done
[ "${CMDS:-0}" -eq 1 ] && ok "./lab.sh scenario normal runs on all endpoints" || bad "lab.sh scenario normal failed"
./lab.sh scenario normal >/dev/null 2>&1 && ok "lab.sh scenario normal ok" || bad "scenario normal"
docker compose exec -T legacy-web python3 /opt/lab/simulate.py health >/dev/null 2>&1 \
  && ok "simulate.py health inside container" || bad "simulate.py health"

# --- summary -------------------------------------------------------------------
printf '\n====================================================\n'
printf 'Integration verification: PASS=%d FAIL=%d SKIP=%d\n' "${PASS}" "${FAIL}" "${SKIP}"
[ "${FAIL}" -eq 0 ] && printf '\033[1;32mALL CHECKS PASSED\033[0m\n' || printf '\033[1;31mFAILURES PRESENT - see above\033[0m\n'
exit $((FAIL > 0))
