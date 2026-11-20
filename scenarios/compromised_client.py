"""Compromised workstation scenario (endpoint: client-01).

All activity is synthetic log data. No real SSH brute force, no real
persistence mechanism, no real data exfiltration - only JSON events and
harmless files whose content is clearly marked as training artifacts.

External actors use documentation-reserved addresses (RFC 5737):
  attacker / brute force source   203.0.113.77  (TEST-NET-3)
  C2 / beacon host                198.51.100.50 (TEST-NET-2)
  exfiltration destination        198.51.100.99 (TEST-NET-2)
Normal internet traffic uses     192.0.2.x     (TEST-NET-1)

Phases (see the expected alerts in exercises/teacher.md):
  A  normal activity (logins, browsing)
  B  failed SSH logins from one external host (brute force -> rule 100122)
  C  successful login for devuser from the same host (compromise -> 100123)
  D  persistence-like artifacts created (FIM + rule 100130)
  E  beaconing to the C2 host (rule 100140)
  F  exfiltration-sized transfer (rule 100141)
  G  trailing normal activity
"""

import os

ATTACKER = "203.0.113.77"
C2_HOST = "198.51.100.50"
EXFIL_HOST = "198.51.100.99"
HOME = os.environ.get("LAB_HOME", "/home/devuser")

BRUTE_USERS = ["root", "admin", "devuser", "test", "oracle", "pi", "ubuntu", "git", "deploy", "jenkins"]


def _write_artifact(eng, path, content, note):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    eng.emit(
        "file_creation",
        path=path,
        user="devuser",
        result="simulated",
        evidence=note,
    )


def engage(eng):
    n = 0

    # A ------------------------------------------------------------ normal activity
    eng.emit("auth_attempt", user="devuser", srcip="10.0.100.55", service="sshd",
             result="success", method="publickey",
             evidence="normal interactive login by an internal user")
    eng.emit("network_connection", dstip="192.0.2.10", dstport=443, protocol="https",
             user="devuser", result="simulated", evidence="normal browser traffic")
    n += 2

    # B --------------------------------------- brute force: failed SSH authentications
    # 10 failures from a single external source (rule 100122 after 8 in 120s)
    for i, user in enumerate(BRUTE_USERS):
        eng.emit("auth_attempt", user=user, srcip=ATTACKER, service="sshd",
                 result="failure", method="password",
                 evidence=f"repeated failed password login (attempt {i + 1} of 10)")
        n += 1

    # C --------------------------- the compromise: successful login from the attacker host
    eng.emit("auth_attempt", user="devuser", srcip=ATTACKER, service="sshd",
             result="success", method="password",
             evidence="successful login from the same host as the failed attempts")
    n += 1

    # D ----------------------------------------------- persistence-looking artifacts
    _write_artifact(
        eng,
        f"{HOME}/.ssh/authorized_keys",
        "# SECURITY-LAB TRAINING ARTIFACT - harmless, not a real key\n"
        "# (simulated persistence mechanism: SSH authorized_keys)\n",
        "SSH authorized_keys created outside the administration process",
    )
    _write_artifact(
        eng,
        f"{HOME}/.config/persist/lab_agent.sh",
        "#!/bin/sh\n# SECURITY-LAB TRAINING ARTIFACT - harmless, does nothing\n"
        "# (simulated persistence mechanism: hidden startup script)\nexit 0\n",
        "hidden script created in user .config (persistence pattern)",
    )
    n += 2

    # E ---------------------------------------------------------------- beaconing
    for _ in range(3):
        eng.emit("network_connection", dstip=C2_HOST, dstport=8443, protocol="tcp",
                 user="devuser", result="simulated",
                 evidence="periodic connection to known suspicious host (beacon pattern)")
        n += 1

    # F ------------------------------------------------------- exfiltration-sized transfer
    eng.emit(
        "suspicious_transfer",
        srcip="10.0.100.55",
        dstip=EXFIL_HOST,
        dstport=4444,
        protocol="tcp",
        bytes=8500000,
        result="simulated",
        evidence="outbound transfer sized like a database dump; nothing real is sent",
    )
    n += 1

    # G ---------------------------------------------------------- trailing normal
    eng.emit("auth_attempt", user="devuser", srcip="10.0.100.55", service="sshd",
             result="success", method="publickey",
             evidence="normal interactive login by an internal user")
    n += 1
    return n
