#!/bin/bash
# ==============================================================================
# Wazuh Security Lab - endpoint entrypoint
#
# 1. installs the baseline application configuration (idempotent: an existing
#    /etc/labapp/app.conf is preserved so student remediations survive
#    restarts; `simulate.py reset` restores the baseline explicitly)
# 2. points the Wazuh agent at the manager
# 3. registers the agent once (the key is persisted in a Docker volume, so
#    restarts keep the same agent identity and never create duplicates)
# 4. starts the agent
# 5. runs the event simulation daemon (normal low-volume activity + watchdog)
# ==============================================================================
set -e

ENDPOINT_NAME="${ENDPOINT_NAME:?ENDPOINT_NAME must be set}"
LAB_PROFILE="${LAB_PROFILE:?LAB_PROFILE must be set}"
WAZUH_MANAGER="${WAZUH_MANAGER:-wazuh-manager}"

LAB_BASE=/opt/lab
APP_CONF=/etc/labapp/app.conf
BASELINE="${LAB_BASE}/baselines/${LAB_PROFILE}.conf"

mkdir -p /etc/labapp /var/log/security-lab /home/devuser /opt/lab/data

# 1. Baseline configuration (only if absent - keeps remediation across restarts)
if [ ! -f "${APP_CONF}" ]; then
    cp "${BASELINE}" "${APP_CONF}"
    if [ "${LAB_PROFILE}" = "legacy-web" ]; then
        chmod 666 "${APP_CONF}"
    else
        chmod 640 "${APP_CONF}"
    fi
    echo "[entrypoint] installed baseline for ${LAB_PROFILE}"
else
    echo "[entrypoint] ${APP_CONF} already present, keeping current state"
fi

# 2. Manager address (idempotent - the value is persisted with the volume)
if ! grep -q "${WAZUH_MANAGER}" /var/ossec/etc/ossec.conf; then
    sed -i "s/WAZUH_MANAGER_ADDRESS/${WAZUH_MANAGER}/" /var/ossec/etc/ossec.conf
fi

# 3. Register once. client.keys lives on a per-endpoint Docker volume, so this
#    runs only the very first time the endpoint starts.
if [ ! -s /var/ossec/etc/client.keys ]; then
    echo "[entrypoint] registering agent '${ENDPOINT_NAME}' with ${WAZUH_MANAGER} ..."
    until /var/ossec/bin/agent-auth -m "${WAZUH_MANAGER}" -p 1515 -A "${ENDPOINT_NAME}"; do
        echo "[entrypoint] manager not ready, retrying in 5s ..."
        sleep 5
    done
else
    echo "[entrypoint] agent '${ENDPOINT_NAME}' already registered (existing key)"
fi

# 4. Start the real Wazuh agent (wazuh-control status is also the container
#    healthcheck used by Docker).
/var/ossec/bin/wazuh-control start
sleep 3
if ! /var/ossec/bin/wazuh-control status >/dev/null 2>&1; then
    echo "[entrypoint] ERROR: wazuh-agent did not start" >&2
    /var/ossec/bin/wazuh-control status || true
    /var/ossec/bin/wazuh-control start || true
fi

# 5. Keep the container running: simulation daemon (normal activity, agent
#    watchdog). This process is PID 1.
exec python3 /opt/lab/simulate.py daemon
