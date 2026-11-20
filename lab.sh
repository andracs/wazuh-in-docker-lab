#!/usr/bin/env bash
# ==============================================================================
# Wazuh Security Lab - host-side CLI wrapper
#
#   ./lab.sh up                      start everything (certs, build, agents)
#   ./lab.sh status                  containers, agents and credentials
#   ./lab.sh scenario <name>         activate a scenario (see "scenarios")
#   ./lab.sh scenarios               list scenarios
#   ./lab.sh reset                   restore scenario state (non-destructive)
#   ./lab.sh reset --volumes         DESTRUCTIVE: also wipe all Wazuh data
#   ./lab.sh down                    stop the lab (data volumes preserved)
#   ./lab.sh verify                  run integration checks against the running lab
#   ./lab.sh test                    run the offline test suite (no Docker needed)
#   ./lab.sh logs [service]          follow logs
# ==============================================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${REPO_DIR}"

ENDPOINTS=(web-safe db-safe legacy-web web-attack client-01)
CERTS_DIR="wazuh/certs/wazuh_indexer_ssl_certs"
GENERATOR_COMPOSE="wazuh/certs/generate-indexer-certs.yml"

blue()   { printf '\033[1;34m%s\033[0m\n' "$*"; }
green()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }
red()    { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    red "ERROR: Docker Compose not found. Install Docker Desktop or the compose plugin."
    exit 1
  fi
}

require_docker() {
  if ! docker info >/dev/null 2>&1; then
    red "ERROR: Docker daemon not reachable. Start Docker Desktop / dockerd first."
    exit 1
  fi
}

load_env() {
  if [ ! -f .env ]; then
    cp .env.example .env
    blue "Created .env from .env.example (training defaults)."
  fi
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
}

api() {
  # Run a Wazuh API call from inside the manager container.
  compose exec -T wazuh-manager \
    curl -sk -u "${API_USER:-wazuh-wui}:${API_PASSWORD:-MyS3cr37P450r.*-}" "$@"
}

agents_summary() {
  api "-w" "https://localhost:55000/agents?agents_list=list" 2>/dev/null \
    | python3 -c '
import json,sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(1)
agents = data.get("data", {}).get("affected_items", [])
for a in agents:
    if a.get("id") in ("000",):
        continue
    print("{:10} {:14} status={}".format(a["id"], a.get("name"), a.get("status")))
conn = sum(1 for a in agents if a.get("status") == "active" and a.get("id") != "000")
print("SUMMARY: {} active agents (expected 5)".format(conn))
' || echo "(Wazuh API not reachable yet)"
}

wait_for_stack() {
  blue "Waiting for the Wazuh stack to become healthy (first start takes 2-5 minutes)..."
  local deadline=$((SECONDS + 420))
  while (( SECONDS < deadline )); do
    local healthy
    healthy=$(compose ps --format json 2>/dev/null | python3 -c '
import json,sys
items = json.load(sys.stdin)
if isinstance(items, dict): items = [items]
print(sum(1 for c in items if c.get("Health") == "healthy"))
' || echo 0)
    if [ "${healthy:-0}" -ge 8 ]; then
      green "All 8 containers healthy."
      return 0
    fi
    sleep 10
  done
  yellow "Timed out waiting for all containers to be healthy. Check: ./lab.sh status"
  return 0
}

cmd_up() {
  require_docker
  load_env
  # Linux hosts need a higher vm.max_map_count for the indexer.
  if [ "$(uname -s)" = "Linux" ] && command -v sysctl >/dev/null 2>&1; then
    if [ "$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)" -lt 262144 ]; then
      yellow "NOTE: vm.max_map_count < 262144. The Wazuh indexer may fail to start."
      yellow "      Fix:  sudo sysctl -w vm.max_map_count=262144"
    fi
  fi
  if [ ! -d "${CERTS_DIR}" ] || [ -z "$(ls -A "${CERTS_DIR}" 2>/dev/null)" ]; then
    blue "Generating local TLS certificates (official Wazuh cert generator, one-off)..."
    compose -f "${GENERATOR_COMPOSE}" run --rm generator
  else
    blue "Reusing existing TLS certificates in ${CERTS_DIR}/."
  fi
  blue "Building endpoint image and starting the lab..."
  compose up -d --build
  wait_for_stack
  print_access
}

print_access() {
  echo
  blue "==================== Wazuh Security Lab ===================="
  echo " Dashboard : https://localhost:${DASHBOARD_PORT:-8443}"
  echo " Login     : ${INDEXER_USERNAME:-admin}"
  echo " Password  : ${INDEXER_PASSWORD:-SecretPassword}   (from .env)"
  echo " Agents    : check ./lab.sh status"
  echo " Scenarios : ./lab.sh scenarios"
  echo "============================================================"
  echo " NOTE: the dashboard uses a self-signed lab CA - accept the browser"
  echo " warning (or import ${CERTS_DIR}/root-ca.pem as trusted CA)."
}

cmd_status() {
  load_env
  compose ps
  echo
  blue "Wazuh agents (via the manager API):"
  agents_summary
}

cmd_scenario() {
  local scenario="${1:-}"
  shift || true
  case "${scenario}" in
    normal)              local targets=("${ENDPOINTS[@]}"); local cmd=normal ;;
    misconfiguration)    local targets=(legacy-web);         local cmd=misconfiguration ;;
    web-attack)          local targets=(web-attack);        local cmd=web-attack ;;
    compromised-client)  local targets=(client-01);         local cmd=compromised-client ;;
    "") red "Usage: ./lab.sh scenario <normal|misconfiguration|web-attack|compromised-client>"; exit 1 ;;
    *)   red "Unknown scenario '${scenario}'. Run: ./lab.sh scenarios"; exit 1 ;;
  esac
  if [ "$#" -gt 0 ]; then
    targets=("$@")
  fi
  require_docker
  for ep in "${targets[@]}"; do
    blue ">>> endpoint ${ep}: ${cmd}"
    compose exec -T "${ep}" python3 /opt/lab/simulate.py "${cmd}"
  done
  green "Scenario '${scenario}' generated. Events appear in the dashboard within ~1 minute."
}

cmd_scenarios() {
  cat <<'EOF'
Available scenarios (./lab.sh scenario <name>):

  normal              low-volume normal activity on ALL five endpoints
  misconfiguration     (re)introduce config problems + unauthorized file change on legacy-web
  web-attack          simulated web attack traffic incl. possible compromise (web-attack)
  compromised-client  failed logins, persistence, beaconing, exfiltration (client-01)

Manual variant (inside one endpoint):
  docker compose exec <endpoint> python3 /opt/lab/simulate.py <scenario> --seed 42
EOF
}

cmd_reset() {
  if [ "${1:-}" = "--volumes" ] || [ "${1:-}" = "--hard" ]; then
    require_docker
    shift
    echo "This will REMOVE all persistent Wazuh data (alerts, agent keys, certificates)."
    read -r -p "Type 'yes' to continue: " REPLY
    [ "${REPLY}" = "yes" ] || { yellow "Aborted."; exit 1; }
    compose down -v
    rm -rf "${CERTS_DIR}"
    green "Full reset done. Start again with: ./lab.sh up"
    return
  fi
  require_docker
  blue "Resetting scenario state on all endpoints (configuration, permissions, event log)..."
  for ep in "${ENDPOINTS[@]}"; do
    compose exec -T "${ep}" python3 /opt/lab/simulate.py reset || true
  done
  blue "Restarting endpoints so FIM/SCA rescans pick up the restored state..."
  compose restart "${ENDPOINTS[@]}" >/dev/null
  green "Scenario state reset (Wazuh data volumes are untouched)."
}

cmd_down() {
  compose down
  yellow "Stopped. All Wazuh data volumes are preserved (use './lab.sh reset --volumes' to wipe)."
}

cmd_verify() {
  require_docker
  bash tests/integration_check.sh
}

cmd_test() {
  (cd tests && python3 -m unittest test_simulation test_rules test_compose -v)
}

cmd_logs() {
  compose logs -f "${1:-}"
}

case "${1:-help}" in
  up)         shift; cmd_up "$@" ;;
  status)     shift; cmd_status "$@" ;;
  scenario)   shift; cmd_scenario "$@" ;;
  scenarios)  cmd_scenarios ;;
  reset)      shift; cmd_reset "$@" ;;
  down)       shift; cmd_down "$@" ;;
  verify)     shift; cmd_verify "$@" ;;
  test)       shift; cmd_test "$@" ;;
  logs)       shift; cmd_logs "$@" ;;
  help|--help|-h) sed -n '2,16p' "$0" | sed 's/^# \{0,2\}//' ;;
  *) red "Unknown command: $1"; exit 1 ;;
esac
