# ==============================================================================
# Wazuh Security Lab - endpoint image
#
# A single lightweight image for all five monitored endpoints. A real, pinned
# Wazuh agent plus the Python event simulation engine. Per-endpoint behaviour
# is controlled by environment variables set in compose.yaml:
#   ENDPOINT_NAME  agent name shown in the Wazuh dashboard
#   LAB_PROFILE    baseline configuration (endpoints/baselines/<name>.conf)
#   WAZUH_MANAGER  manager hostname (compose service name)
# ==============================================================================
FROM debian:bookworm-slim

ARG WAZUH_VERSION=4.14.10
ARG WAZUH_APT_VERSION=${WAZUH_VERSION}-1

# --- Wazuh agent (pinned to the same version as the manager) -----------------
# Do not start services during package installation inside the image build.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod +x /usr/sbin/policy-rc.d \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg apt-transport-https procps python3 python3-minimal \
    && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH -o /usr/share/keyrings/wazuh-keyring.asc \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh-keyring.asc] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        wazuh-agent="${WAZUH_APT_VERSION}" \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/sbin/policy-rc.d

# --- Lab application configuration directory (monitored by SCA and FIM) ------
RUN mkdir -p /etc/labapp /var/log/security-lab /home/devuser /opt/lab/data

# --- Wazuh agent configuration and custom SCA policy --------------------------
COPY endpoints/ossec.conf /var/ossec/etc/ossec.conf
COPY endpoints/sca/security_lab_baseline.yml /var/ossec/ruleset/sca/security_lab_baseline.yml
RUN chmod 0640 /var/ossec/etc/ossec.conf /var/ossec/ruleset/sca/security_lab_baseline.yml

# --- Simulation engine ---------------------------------------------------------
COPY endpoints/simulate.py /opt/lab/simulate.py
COPY endpoints/entrypoint.sh /opt/lab/entrypoint.sh
COPY scenarios/ /opt/lab/scenarios/
COPY endpoints/baselines/ /opt/lab/baselines/
RUN chmod -R 0644 /opt/lab/baselines /opt/lab/scenarios \
    && chmod 0755 /opt/lab/simulate.py /opt/lab/entrypoint.sh

# The entrypoint keeps the container running; there is no need for sshd, a web
# server or any listening service - all activity is simulated log data.
ENTRYPOINT ["/opt/lab/entrypoint.sh"]
