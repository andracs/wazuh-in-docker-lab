"""Normal, low-volume activity for every endpoint profile.

None of these events may trigger the lab's malicious-event rules
(verified by tests/test_rules.py and tests/integration_check.sh).
"""

import os

PROFILE = os.environ.get("LAB_PROFILE", os.environ.get("ENDPOINT_NAME", ""))

WEB_PATHS = [
    "/", "/index.html", "/products", "/products.php?id=3", "/about.html",
    "/static/style.css", "/static/app.js", "/api/v1/status", "/login",
]
WEB_CLIENTS = ["10.0.100.23", "10.0.100.31", "10.0.100.42", "10.0.100.55"]
INTERNAL_SERVERS = ["10.0.1.10", "10.0.1.11"]
NORMAL_INTERNET = ["192.0.2.10", "192.0.2.25"]  # TEST-NET-1: safe placeholders


def generate(eng, count=1):
    """Emit `count` normal events for the current profile."""
    profile = eng_profile(eng)
    for _ in range(count):
        if profile in ("web-safe", "web-attack", "legacy-web"):
            _web_event(eng)
        elif profile == "db-safe":
            _db_event(eng)
        else:  # client-01 and unknown profiles: workstation behaviour
            _client_event(eng)


def eng_profile(eng):
    profile = os.environ.get("LAB_PROFILE", os.environ.get("ENDPOINT_NAME", ""))
    return profile or PROFILE


def _web_event(eng):
    eng.emit(
        "http_request",
        srcip=eng.rng.choice(WEB_CLIENTS),
        method=eng.rng.choice(["GET", "GET", "GET", "POST"]),
        url=eng.rng.choice(WEB_PATHS),
        status=200,
        bytes=eng.rng.randint(1200, 48000),
        dstip=eng.rng.choice(INTERNAL_SERVERS),
        result="simulated",
        evidence="normal browsing by an internal client",
    )


def _db_event(eng):
    if eng.rng.random() < 0.7:
        eng.emit(
            "db_query",
            user=eng.rng.choice(["app_ro", "app_ro"]),
            statement="SELECT id, name FROM customers WHERE id = ?",
            rows=eng.rng.randint(1, 40),
            dstip="10.0.1.20",
            service="postgres",
            result="simulated",
            evidence="parameterized read-only query",
        )
    else:
        eng.emit(
            "auth_attempt",
            user="app_ro",
            srcip="10.0.1.10",
            service="postgres",
            result="success",
            method="scram-sha-256",
            evidence="application login with least-privilege account",
        )


def _client_event(eng):
    roll = eng.rng.random()
    if roll < 0.4:
        eng.emit(
            "auth_attempt",
            user="devuser",
            srcip="10.0.100.55",
            service="sshd",
            result="success",
            method="publickey",
            evidence="normal interactive login by an internal user",
        )
    elif roll < 0.8:
        eng.emit(
            "network_connection",
            dstip=eng.rng.choice(NORMAL_INTERNET),
            dstport=443,
            protocol="https",
            user="devuser",
            result="simulated",
            evidence="normal browser traffic",
        )
    else:
        eng.emit(
            "http_request",
            srcip="10.0.100.55",
            method="GET",
            url=eng.rng.choice(["/updates/check", "/", "/index.html"]),
            status=200,
            bytes=eng.rng.randint(1500, 30000),
            result="simulated",
            evidence="normal client request",
        )
