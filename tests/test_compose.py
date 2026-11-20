"""Offline validation of the deployment artifacts.

  - compose.yaml: exactly the 8 required long-running services, endpoint
    isolation (no published ports), dashboard bound to localhost, healthchecks,
    restart policies, resource limits, persistent volumes and stable agent
    identity volumes.
  - Custom SCA policy: parses and the endpoint baselines produce the intended
    check results (compliant endpoints pass, legacy-web fails exactly the
    three intended checks).

`docker compose config` (the authoritative validation) is executed by
tests/smoke-test.sh and tests/integration_check.sh.
"""

import os
import re
import xml.etree.ElementTree as ET
import unittest

import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMPOSE = os.path.join(REPO_ROOT, "compose.yaml")
SCA = os.path.join(REPO_ROOT, "endpoints", "sca", "security_lab_baseline.yml")
BASELINES = os.path.join(REPO_ROOT, "endpoints", "baselines")

INFRA = {"wazuh-manager", "wazuh-indexer", "wazuh-dashboard"}
ENDPOINTS = {"web-safe", "db-safe", "legacy-web", "web-attack", "client-01"}


class TestCompose(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(COMPOSE, encoding="utf-8") as fh:
            cls.doc = yaml.safe_load(fh)
        cls.services = cls.doc["services"]

    def test_exactly_eight_long_running_services(self):
        self.assertEqual(set(self.services), INFRA | ENDPOINTS)

    def test_endpoints_publish_no_ports(self):
        for ep in ENDPOINTS:
            self.assertIsNone(self.services[ep].get("ports"),
                              f"{ep} must not publish ports")

    def test_dashboard_is_localhost_only(self):
        ports = self.services["wazuh-dashboard"]["ports"]
        self.assertEqual(len(ports), 1)
        value = ports[0]
        self.assertTrue(value.startswith("127.0.0.1:"), value)
        self.assertTrue(value.endswith(":5601"), value)
        host_port = value.split(":", 1)[1].rsplit(":", 1)[0]
        self.assertRegex(host_port, r"^\$\{?[A-Za-z_]+")  # variable or number

    def test_every_service_has_restart_policy_and_healthcheck(self):
        for name, svc in self.services.items():
            self.assertIn("restart", svc, name)
            self.assertIn("healthcheck", svc, name)

    def test_endpoints_have_agent_identity_volumes(self):
        for ep in ENDPOINTS:
            volumes = self.services[ep]["volumes"]
            self.assertTrue(any(v.endswith(":/var/ossec/etc") for v in volumes),
                            ep)
            name = volumes[0].split(":")[0]
            self.assertIn(name, self.doc["volumes"], ep)

    def test_endpoints_declare_profiles_and_manager(self):
        for ep in ENDPOINTS:
            env = self.services[ep]["environment"]
            self.assertEqual(env["ENDPOINT_NAME"], ep)
            self.assertEqual(env["LAB_PROFILE"], ep)
            self.assertEqual(env["WAZUH_MANAGER"], "wazuh-manager")

    def test_manager_mounts_rules_and_manager_config(self):
        mounts = self.services["wazuh-manager"]["volumes"]
        self.assertTrue(any(v.startswith("./wazuh/rules/") for v in mounts))
        self.assertTrue(any(v.startswith("./wazuh/manager/ossec.conf") for v in mounts))

    def test_manager_and_indexer_have_persistent_data_volumes(self):
        mounts = "\n".join(self.services["wazuh-manager"]["volumes"])
        self.assertIn(":/var/ossec/logs", mounts)
        self.assertIn("wazuh-indexer-data:/var/lib/wazuh-indexer",
                      "\n".join(self.services["wazuh-indexer"]["volumes"]))

    def test_dedicated_network(self):
        names = set()
        for svc in self.services.values():
            names.update(svc.get("networks", []))
        self.assertEqual(names, {"labnet"})
        self.assertEqual(self.doc["networks"]["labnet"]["name"],
                         "wazuh-security-lab-net")

    def test_resource_limits_set(self):
        for name, svc in self.services.items():
            self.assertIn("mem_limit", svc, name)
            self.assertIn("cpus", svc, name)

    def test_pinned_versions_named_everywhere(self):
        self.assertIn("WAZUH_VERSION", open(os.path.join(REPO_ROOT, ".env.example")).read())
        self.assertIn("${WAZUH_VERSION:-4.14.10}",
                      self.services["wazuh-manager"]["image"])


class TestScaBaseline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import yaml as _yaml
        with open(SCA, encoding="utf-8") as fh:
            cls.sca = _yaml.safe_load(fh)

    def test_policy_metadata(self):
        policy = self.sca["policy"]
        self.assertEqual(policy["id"], "security_lab_baseline")
        self.assertEqual(policy["file"], "security_lab_baseline.yml")
        self.assertIn("undervisnings", policy["name"])

    def test_five_expected_checks_exist(self):
        ids = [c["id"] for c in self.sca["checks"]]
        self.assertEqual(sorted(ids), [10100, 10101, 10102, 10103, 10104])
        titles = " ".join(c["title"].lower() for c in self.sca["checks"])
        for word in ("debug", "anonym", "filtilladelser", "audit", "administratoradgang"):
            self.assertIn(word, titles)
        for c in self.sca["checks"]:
            self.assertIn("remediation", c)

    def test_disclaimer_present(self):
        text = open(SCA, encoding="utf-8").read()
        self.assertIn("NOT imply CIS", text)


def evaluate_baseline(endpoint):
    """Simulate the SCA checks against the baseline config of one endpoint."""
    conf = open(os.path.join(BASELINES, f"{endpoint}.conf"), encoding="utf-8").read()
    kv = {
        m.group(1): m.group(2).strip()
        for m in re.finditer(r"^\s*(\w+)\s*=\s*(.+)$", conf, re.M)
    }
    mode = "640" if endpoint != "legacy-web" else "666"
    results = {
        10100: kv.get("debug") == "false",
        10101: kv.get("anonymous_access") == "false",
        10102: mode in ("600", "640"),
        10103: kv.get("audit_log") == "true",
        10104: kv.get("restrict_admin_access") == "true",
    }
    return results


class TestWazuhDeploymentRegressions(unittest.TestCase):
    """Regressions found during live deployment on Apple Silicon."""

    @classmethod
    def setUpClass(cls):
        with open(COMPOSE, encoding="utf-8") as fh:
            cls.doc = yaml.safe_load(fh)
        cls.services = cls.doc["services"]

    def test_indexer_mounts_internal_users(self):
        # Without this mount the wazuh-indexer image keeps the OpenSearch
        # DEMO internal_users.yml -> admin password is literally "admin" and
        # every component authenticating with SecretPassword fails
        # (Unauthorized), so no alerts are ever delivered to the index.
        mounts = "\n".join(self.services["wazuh-indexer"]["volumes"])
        self.assertIn(
            "internal_users.yml:/usr/share/wazuh-indexer/config/opensearch-security/internal_users.yml",
            mounts)

    def test_rule_fields_do_not_use_osregex_alternation(self):
        # Wazuh's default OS_Regex engine does NOT support '|'; when a field
        # pattern needs alternation it must declare type="pcre2"
        # (regression test for the "Syntax error on tag 'event_type' in rule
        # 100102" manager startup failure).
        import xml.etree.ElementTree as ET
        tree = ET.parse(os.path.join(REPO_ROOT, "wazuh", "rules",
                                     "security_lab_rules.xml"))
        for r in tree.getroot().findall("rule"):
            for f in r.findall("field"):
                if f.get("type") in (None, "osregex", "osmatch"):
                    self.assertNotIn(
                        "|", (f.text or ""),
                        f"rule {r.get('id')} field {f.get('name')} "
                        "must use pcre2 for alternation")


class TestBaselineIntendedResults(unittest.TestCase):
    def test_compliant_endpoints_pass_all_checks(self):
        for ep in ("web-safe", "db-safe", "client-01", "web-attack"):
            results = evaluate_baseline(ep)
            failed = [k for k, v in results.items() if not v]
            self.assertEqual(failed, [], ep)

    def test_legacy_web_fails_exactly_three_checks(self):
        results = evaluate_baseline("legacy-web")
        failed = sorted(k for k, v in results.items() if not v)
        self.assertEqual(failed, [10100, 10101, 10102])

    def test_compose_baseline_modes_match_legacy_scenario(self):
        with open(os.path.join(REPO_ROOT, "endpoints", "entrypoint.sh"),
                  encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn('chmod 666 "${APP_CONF}"', text)
        self.assertIn('chmod 640 "${APP_CONF}"', text)


if __name__ == "__main__":
    unittest.main()


class TestManagerConfig(unittest.TestCase):
    """The manager ossec.conf is upstream's official file (multiple root
    ossec_config elements, accepted by Wazuh's XML parser)."""

    def test_manager_config_structure(self):
        data = open(os.path.join(REPO_ROOT, "wazuh", "manager", "ossec.conf"),
                    encoding="utf-8").read()
        ET.fromstring("<wrapper>" + data + "</wrapper>")
        self.assertIn("<auth>", data)
        self.assertIn("<use_password>no</use_password>", data)
        self.assertIn("https://wazuh.indexer:9200", data)

    def test_rule_ids_do_not_collide_with_stock_ranges(self):
        tree = ET.parse(os.path.join(REPO_ROOT, "wazuh", "rules",
                                     "security_lab_rules.xml"))
        ids = [int(r.get("id")) for r in tree.getroot().findall("rule")]
        for rid in ids:
            self.assertTrue(100100 <= rid <= 101999, rid)
        self.assertEqual(len(ids), len(set(ids)))
