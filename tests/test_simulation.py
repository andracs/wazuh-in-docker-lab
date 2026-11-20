"""Unit tests for the Wazuh Security Lab event simulation engine.

Runs entirely offline (no Docker, no Wazuh): the engine's paths are
redirected into a temporary directory through the LAB_* environment
variables documented in endpoints/simulate.py.

Run:  python3 -m unittest test_simulation -v   (from the tests/ directory)
"""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIM = os.path.join(REPO_ROOT, "endpoints", "simulate.py")

COMMON_FIELDS = {"timestamp", "sequence", "event_type", "endpoint",
                 "case_id", "synthetic"}
ENDPOINTS = ["web-safe", "db-safe", "legacy-web", "web-attack", "client-01"]


class LabBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wazuh-lab-test-")
        self.home = os.path.join(self.tmp, "home", "devuser")
        os.makedirs(self.home, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def env(self, endpoint):
        env = os.environ.copy()
        env.update({
            "LAB_LOG_PATH": os.path.join(self.tmp, f"{endpoint}-events.json"),
            "LAB_APP_CONF": os.path.join(self.tmp, f"{endpoint}-app.conf"),
            "LAB_BASELINE_DIR": os.path.join(REPO_ROOT, "endpoints", "baselines"),
            "LAB_DATA_DIR": os.path.join(self.tmp, "data"),
            "LAB_HOME": self.home,
            "ENDPOINT_NAME": endpoint,
            "LAB_PROFILE": endpoint,
        })
        return env

    def run_sim(self, env, *args):
        proc = subprocess.run(
            [sys.executable, SIM, *args], env=env,
            capture_output=True, text=True, timeout=60,
        )
        return proc

    def install_baseline(self, env):
        baseline = os.path.join(REPO_ROOT, "endpoints", "baselines",
                               env["LAB_PROFILE"] + ".conf")
        shutil.copy(baseline, env["LAB_APP_CONF"])
        os.chmod(env["LAB_APP_CONF"],
                 0o666 if env["LAB_PROFILE"] == "legacy-web" else 0o640)

    def events(self, env):
        path = env["LAB_LOG_PATH"]
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]


class TestSchema(LabBase):
    def test_normal_events_valid_for_all_profiles(self):
        for ep in ENDPOINTS:
            env = self.env(ep)
            proc = self.run_sim(env, "normal", "--count", "10", "--seed", "1")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            events = self.events(env)
            self.assertEqual(len(events), 10, ep)
            for ev in events:
                self.assertTrue(COMMON_FIELDS.issubset(ev), (ep, ev))
                self.assertEqual(ev["case_id"], "SECURITY-LAB")
                self.assertTrue(ev["synthetic"] is True)
                self.assertEqual(ev["endpoint"], ep)
                self.assertIn(ev["event_type"], {
                    "http_request", "db_query", "auth_attempt",
                    "network_connection"})
                self.assertIsInstance(ev["sequence"], int)

    def test_sequence_is_monotonic_across_runs(self):
        env = self.env("web-safe")
        self.install_baseline(env)
        self.run_sim(env, "normal", "--count", "3", "--seed", "1")
        self.run_sim(env, "normal", "--count", "5", "--seed", "1")
        seqs = [e["sequence"] for e in self.events(env)]
        self.assertEqual(seqs, sorted(seqs))
        self.assertEqual(len(set(seqs)), len(seqs))


class TestNormalIsClean(LabBase):
    def test_normal_activity_never_contains_attack_indicators(self):
        for ep in ENDPOINTS:
            env = self.env(ep)
            self.run_sim(env, "normal", "--count", "50", "--seed", "3")
            for ev in self.events(env):
                blob = json.dumps(ev)
                self.assertNotIn("203.0.113.", blob, ep)      # attacker range
                self.assertNotIn("198.51.100.", blob, ep)     # C2/exfil range
                self.assertNotIn("UNION", blob.upper())       # SQL injection
                self.assertNotIn("../", blob)                 # traversal
                self.assertNotIn("cmd=", blob)                 # webshell
                self.assertNotIn("suspicious_transfer", ev["event_type"])
                self.assertNotIn("failure", str(ev.get("result", "")))


class TestSeededDeterminism(LabBase):
    def test_same_seed_same_events(self):
        env = self.env("web-attack")
        strip = lambda e: {k: v for k, v in e.items() if k != "timestamp"}
        self.run_sim(env, "normal", "--count", "20", "--seed", "42")
        run_a = self.events(env)
        open(env["LAB_LOG_PATH"], "w").close()
        self.run_sim(env, "normal", "--count", "20", "--seed", "42")
        run_b = self.events(env)
        self.assertEqual([strip(e) for e in run_a], [strip(e) for e in run_b])

    def test_seed_with_second_subcommand_position(self):
        # ./lab.sh invokes: simulate.py normal --count 5 --seed 7
        env = self.env("web-safe")
        proc = self.run_sim(env, "normal", "--count", "5", "--seed", "7")
        self.assertEqual(proc.returncode, 0, proc.stderr)


class TestScenarios(LabBase):
    def test_misconfiguration_creates_three_problems(self):
        env = self.env("legacy-web")
        self.install_baseline(env)
        proc = self.run_sim(env, "misconfiguration", "--seed", "1")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        conf = open(env["LAB_APP_CONF"], encoding="utf-8").read()
        self.assertRegex(conf, r"(?m)^\s*debug\s*=\s*true")
        self.assertRegex(conf, r"(?m)^\s*anonymous_access\s*=\s*true")
        mode = stat.S_IMODE(os.stat(env["LAB_APP_CONF"]).st_mode)
        self.assertEqual(oct(mode), "0o666")
        self.assertIn("unscheduled", conf)  # FIM change marker appended
        # one config_change event emitted for the timeline
        self.assertEqual([e["event_type"] for e in self.events(env)],
                         ["config_change"])

    def test_misconfiguration_denied_on_compliant_endpoint(self):
        env = self.env("web-safe")
        self.install_baseline(env)
        proc = self.run_sim(env, "misconfiguration")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("legacy-web", proc.stderr)

    def test_web_attack_scenario_content(self):
        env = self.env("web-attack")
        proc = self.run_sim(env, "web-attack", "--seed", "1")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        events = self.events(env)
        urls = [e.get("url", "") for e in events if e["event_type"] == "http_request"]
        joined = " ".join(urls).upper()
        self.assertIn("UNION", joined)                       # SQL injection present
        self.assertIn("../", " ".join(urls))                 # traversal present
        self.assertIn("CMD=", joined)                        # webshell present
        self.assertEqual(events[0]["lab_scenario"], "web-attack")
        statuses = [e.get("status") for e in events]
        self.assertGreaterEqual(statuses.count(404), 8)      # scanning errors
        self.assertGreaterEqual(statuses.count(500), 4)     # error burst
        self.assertGreaterEqual(statuses.count(200), 11)    # normal + compromise

    def test_web_attack_denied_on_db_endpoint(self):
        env = self.env("db-safe")
        proc = self.run_sim(env, "web-attack")
        self.assertEqual(proc.returncode, 2)

    def test_compromised_client_scenario_content(self):
        env = self.env("client-01")
        proc = self.run_sim(env, "compromised-client", "--seed", "1")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        events = self.events(env)
        failures = [e for e in events if e["event_type"] == "auth_attempt"
                    and e["result"] == "failure"]
        self.assertEqual(len(failures), 10)                  # brute force
        self.assertTrue(all(e["srcip"] == "203.0.113.77" for e in failures))
        compromise = [e for e in events if e["event_type"] == "auth_attempt"
                      and e["result"] == "success"
                      and e["srcip"] == "203.0.113.77"]
        self.assertEqual(len(compromise), 1)                 # the compromise
        transfers = [e for e in events if e["event_type"] == "suspicious_transfer"]
        self.assertEqual(len(transfers), 1)
        self.assertEqual(transfers[0]["bytes"], 8500000)
        self.assertEqual(transfers[0]["dstip"], "198.51.100.99")
        # persistence-like artifacts really created (harmless content)
        ak = os.path.join(self.home, ".ssh", "authorized_keys")
        self.assertTrue(os.path.exists(ak))
        self.assertIn("HARMLESS", open(ak).read().upper())

    def test_compromised_client_denied_on_web_endpoint(self):
        env = self.env("web-safe")
        proc = self.run_sim(env, "compromised-client")
        self.assertEqual(proc.returncode, 2)


class TestReset(LabBase):
    def test_reset_restores_baseline_and_removes_artifacts(self):
        env = self.env("client-01")
        self.install_baseline(env)
        self.run_sim(env, "compromised-client", "--seed", "2")
        self.assertTrue(os.path.exists(os.path.join(self.home, ".ssh",
                                                   "authorized_keys")))
        proc = self.run_sim(env, "reset", "--seed", "2")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.home, ".ssh",
                                                     "authorized_keys")))
        conf = open(env["LAB_APP_CONF"], encoding="utf-8").read()
        self.assertRegex(conf, r"(?m)^\s*debug\s*=\s*false")
        mode = stat.S_IMODE(os.stat(env["LAB_APP_CONF"]).st_mode)
        self.assertEqual(oct(mode), "0o640")
        events = self.events(env)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "lab_reset")

    def test_reset_is_idempotent(self):
        env = self.env("legacy-web")
        self.install_baseline(env)
        for _ in range(3):
            proc = self.run_sim(env, "reset", "--seed", "5")
            self.assertEqual(proc.returncode, 0, proc.stderr)
        mode = stat.S_IMODE(os.stat(env["LAB_APP_CONF"]).st_mode)
        self.assertEqual(oct(mode), "0o666")  # legacy baseline restores insecure state


if __name__ == "__main__":
    unittest.main()
