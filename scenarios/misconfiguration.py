"""Misconfiguration scenario (endpoint: legacy-web).

Introduces the three intentional configuration problems plus one simulated
unauthorized change to a FIM-monitored file:

  1. debug=true            -> lab SCA check 10100 fails
  2. anonymous_access=true -> lab SCA check 10101 fails
  3. chmod 666 app.conf    -> lab SCA check 10102 fails
  4. unauthorized comment appended to app.conf -> FIM (syscheck) alert

Remediation (students): set the keys back to false, chmod 640, remove the
comment, then rerun the SCA scan (docker compose restart legacy-web triggers a
scan-on-start, or wait up to 30 minutes for the scheduled scan).
"""

import os

APP_CONF = os.environ.get("LAB_APP_CONF", "/etc/labapp/app.conf")


def _set_key(path, key, value):
    lines = []
    found = False
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip().startswith(f"{key}="):
                lines.append(f"{key}={value}\n")
                found = True
            else:
                lines.append(line)
    if not found:
        lines.append(f"{key}={value}\n")
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)


def engage(eng):
    before_mode = oct(os.stat(APP_CONF).st_mode & 0o777) if os.path.exists(APP_CONF) else None

    _set_key(APP_CONF, "debug", "true")
    _set_key(APP_CONF, "anonymous_access", "true")
    os.chmod(APP_CONF, 0o666)

    # Simulated unauthorized change to the monitored configuration file.
    # FIM (syscheck, realtime) will raise an integrity-change alert.
    unauthorized_marker = "# hotfix 2025-06-11 applied by external contractor (unscheduled)\n"
    with open(APP_CONF, "a", encoding="utf-8") as fh:
        fh.write(unauthorized_marker)

    eng.emit(
        "config_change",
        detail="debug=true, anonymous_access=true, permissions 666, unauthorized comment appended",
        path=APP_CONF,
        user="contractor",
        previous_mode=before_mode,
        new_mode="0o666",
        result="simulated",
        evidence="unscheduled change outside the change window",
    )
    return 1
