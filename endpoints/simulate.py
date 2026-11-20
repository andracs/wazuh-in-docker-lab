#!/usr/bin/env python3
"""Wazuh Security Lab - event simulation engine.

Produces structured, single-line JSON events in a predictable log file
(default: /var/log/security-lab/events.json) which the local Wazuh agent
collects (log_format=json) and the manager analyses with the custom rules
in wazuh/rules/security_lab_rules.xml.

Every event is clearly marked as synthetic:

    "case_id": "SECURITY-LAB", "synthetic": true

Usage (inside an endpoint container, or via ./lab.sh scenario <name>):

    python3 /opt/lab/simulate.py normal
    python3 /opt/lab/simulate.py misconfiguration
    python3 /opt/lab/simulate.py web-attack
    python3 /opt/lab/simulate.py compromised-client
    python3 /opt/lab/simulate.py reset
    python3 /opt/lab/simulate.py daemon
    python3 /opt/lab/simulate.py health

All paths can be overridden with environment variables (used by the test
suite so the engine can run outside a container):

    LAB_LOG_PATH       event log file       (default /var/log/security-lab/events.json)
    LAB_APP_CONF       app config file      (default /etc/labapp/app.conf)
    LAB_BASELINE_DIR   baseline configs     (default /opt/lab/baselines)
    LAB_DATA_DIR       scenario data dir    (default /opt/lab/data)
    ENDPOINT_NAME      endpoint identity    (default: hostname)
    LAB_PROFILE        baseline profile     (default: ENDPOINT_NAME)
"""

import argparse
import datetime
import json
import os
import random
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
# /opt/lab (image) or <repo>/endpoints (local tests): make the scenarios
# package importable in both layouts.
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))

from scenarios import (  # noqa: E402
    compromised_client,
    misconfiguration,
    normal,
    web_attack,
)

LOG_PATH = os.environ.get("LAB_LOG_PATH", "/var/log/security-lab/events.json")
APP_CONF = os.environ.get("LAB_APP_CONF", "/etc/labapp/app.conf")
BASELINE_DIR = os.environ.get("LAB_BASELINE_DIR",
                              os.path.join(os.path.dirname(os.path.abspath(__file__)), "baselines"))
DATA_DIR = os.environ.get("LAB_DATA_DIR", "/opt/lab/data")
ENDPOINT_NAME = os.environ.get("ENDPOINT_NAME") or os.uname().nodename
LAB_PROFILE = os.environ.get("LAB_PROFILE", ENDPOINT_NAME)

DAEMON_INTERVAL = int(os.environ.get("LAB_DAEMON_INTERVAL", "25"))

WEB_PROFILES = {"web-safe", "web-attack", "legacy-web"}


class Engine:
    """Writes synthetic JSON events to the lab event log."""

    def __init__(self, seed=42, scenario=None):
        self.rng = random.Random(seed)
        self.scenario = scenario
        self.sequence = self._count_log_lines()
        self.start_time = datetime.datetime.now(datetime.timezone.utc)

    # ------------------------------------------------------------------ utils
    @staticmethod
    def _count_log_lines():
        if not os.path.exists(LOG_PATH):
            return 0
        with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as fh:
            return sum(1 for line in fh if line.strip())

    def emit(self, event_type, **fields):
        """Append one synthetic event as a single JSON line."""
        self.sequence += 1
        event = {
            "timestamp": fields.pop(
                "timestamp",
                datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            ),
            "sequence": self.sequence,
            "event_type": event_type,
            "endpoint": fields.pop("endpoint", ENDPOINT_NAME),
            "case_id": "SECURITY-LAB",
            "synthetic": True,
        }
        if self.scenario:
            event["lab_scenario"] = self.scenario
        event.update(fields)
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, separators=(",", ":"), ensure_ascii=False) + "\n")
        return event


# ============================================================================ #
# Commands                                                                     #
# ============================================================================ #

def cmd_normal(args):
    eng = Engine(seed=args.seed)
    normal.generate(eng, count=args.count)
    print(f"normal: wrote {args.count} normal events to {LOG_PATH}")


def cmd_misconfiguration(args):
    if not os.path.exists(APP_CONF):
        print(f"misconfiguration: {APP_CONF} not found - start the endpoint first "
              "(the entrypoint installs the baseline configuration)", file=sys.stderr)
        return 2
    if LAB_PROFILE != "legacy-web" and not args.force:
        print(
            f"misconfiguration: denied on profile {LAB_PROFILE!r} "
            "(this scenario is intended for legacy-web; use --force to override)",
            file=sys.stderr,
        )
        return 2
    eng = Engine(seed=args.seed, scenario="misconfiguration")
    misconfiguration.engage(eng)
    print("misconfiguration: applied 3 configuration problems + unauthorized file change")
    return 0


def cmd_web_attack(args):
    if LAB_PROFILE not in WEB_PROFILES and not args.force:
        print(
            f"web-attack: denied on profile {LAB_PROFILE!r} "
            "(this scenario is intended for the web endpoints; use --force to override)",
            file=sys.stderr,
        )
        return 2
    eng = Engine(seed=args.seed, scenario="web-attack")
    events = web_attack.engage(eng)
    print(f"web-attack: wrote {events} events (normal browsing, SQLi, traversal, scanning, possible compromise)")
    return 0


def cmd_compromised_client(args):
    if LAB_PROFILE not in {"client-01"} and not args.force:
        print(
            f"compromised-client: denied on profile {LAB_PROFILE!r} "
            "(this scenario is intended for client-01; use --force to override)",
            file=sys.stderr,
        )
        return 2
    eng = Engine(seed=args.seed, scenario="compromised-client")
    events = compromised_client.engage(eng)
    print(f"compromised-client: wrote {events} events (failed logins, persistence, beaconing, exfiltration)")
    return 0


def cmd_reset(args):
    """Restore baseline state: config, permissions, suspicious artifacts, log."""
    baseline = os.path.join(BASELINE_DIR, f"{LAB_PROFILE}.conf")
    if os.path.exists(baseline):
        os.makedirs(os.path.dirname(APP_CONF), exist_ok=True)
        with open(baseline, "r", encoding="utf-8") as src, open(APP_CONF, "w", encoding="utf-8") as dst:
            dst.write(src.read())
        mode = 0o666 if LAB_PROFILE == "legacy-web" else 0o640
        os.chmod(APP_CONF, mode)
        print(f"reset: restored {APP_CONF} from baseline ({baseline}), mode {oct(mode)}")
    else:
        print(f"reset: no baseline found for profile {LAB_PROFILE!r}", file=sys.stderr)
    # Remove scenario artifacts (persistence-like training files)
    home = os.environ.get("LAB_HOME", "/home/devuser")
    artifacts = [
        os.path.join(home, ".ssh/authorized_keys"),
        os.path.join(home, ".config/persist/lab_agent.sh"),
    ]
    for path in artifacts:
        if os.path.exists(path):
            os.remove(path)
            print(f"reset: removed {path}")
    # Clear the synthetic event log and log a reset marker
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "w", encoding="utf-8") as fh:
        pass
    Engine(seed=args.seed).emit("lab_reset", reason="scenario state reset", result="simulated")
    print(f"reset: truncated {LOG_PATH} and wrote reset marker")
    return 0


def cmd_daemon(_args):
    """Background mode: low-volume normal activity + agent watchdog (PID 1)."""
    print(f"daemon: simulating normal activity for {ENDPOINT_NAME} ({LAB_PROFILE})", flush=True)
    eng = Engine(seed=int(os.environ.get("LAB_DAEMON_SEED", "42")))
    watchdog_counter = 0
    while True:
        try:
            normal.generate(eng, count=1)
        except Exception as exc:  # never let the container die
            print(f"daemon: event generation failed: {exc}", file=sys.stderr, flush=True)
        watchdog_counter += 1
        if watchdog_counter % 2 == 0:
            _ensure_agent_running()
        time.sleep(DAEMON_INTERVAL)


def _ensure_agent_running():
    try:
        rc = subprocess.run(
            ["/var/ossec/bin/wazuh-control", "status"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).returncode
        if rc != 0:
            print("daemon: wazuh-agent not running, restarting", flush=True)
            subprocess.run(["/var/ossec/bin/wazuh-control", "start"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        # Outside a container (e.g. unit tests) there is no wazuh-control.
        pass


def cmd_health(_args):
    """Machine-readable health status (used by lab.sh and the test suite)."""
    try:
        agent = subprocess.run(
            ["/var/ossec/bin/wazuh-control", "status"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).returncode == 0
    except FileNotFoundError:
        agent = None
    try:
        mode = oct(os.stat(APP_CONF).st_mode & 0o777)
    except FileNotFoundError:
        mode = None
    lines = Engine._count_log_lines()
    status = {"endpoint": ENDPOINT_NAME, "profile": LAB_PROFILE,
              "agent_running": agent, "log": LOG_PATH, "log_lines": lines,
              "app_conf_mode": mode, "synthetic": True}
    print(json.dumps(status))
    return 0 if agent is not False else 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="simulate.py",
        description="Wazuh Security Lab: synthetic telemetry generator",
    )
    seed_parser = argparse.ArgumentParser(add_help=False)
    seed_parser.add_argument("--seed", type=int, default=42,
                             help="seed for controlled randomness (deterministic scenarios)")
    # --seed is accepted both before and after the scenario name.
    scenarios = parser.add_subparsers(dest="scenario", required=True, parser_class=type(parser))

    p = scenarios.add_parser("normal", parents=[seed_parser], help="low-volume normal activity")
    p.add_argument("--count", type=int, default=20)
    p.set_defaults(func=cmd_normal)

    p = scenarios.add_parser("misconfiguration", parents=[seed_parser],
                              help="(re)introduce configuration problems on legacy-web")
    p.add_argument("--force", action="store_true",
                   help="allow on other profiles (TEACHER/TEST ONLY)")
    p.set_defaults(func=cmd_misconfiguration)

    p = scenarios.add_parser("web-attack", parents=[seed_parser],
                              help="simulated attack traffic against a web endpoint")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_web_attack)

    p = scenarios.add_parser("compromised-client", parents=[seed_parser],
                              help="simulated workstation compromise on client-01")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_compromised_client)

    p = scenarios.add_parser("reset", parents=[seed_parser],
                              help="restore baseline configuration and clear scenario state")
    p.set_defaults(func=cmd_reset)

    p = scenarios.add_parser("daemon", parents=[seed_parser], help="background mode (container entrypoint)")
    p.set_defaults(func=cmd_daemon)

    p = scenarios.add_parser("health", parents=[seed_parser], help="print JSON health status")
    p.set_defaults(func=cmd_health)

    args = parser.parse_args(argv)
    rc = args.func(args)
    return 0 if rc is None else rc


if __name__ == "__main__":
    sys.exit(main())
