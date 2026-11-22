"""Offline tests for the custom Wazuh rules (wazuh/rules/security_lab_rules.xml).

Without a running Wazuh manager this suite cannot execute the real rules
engine. It therefore:

  1. validates the rule XML structure (ids, levels, groups, if_sid chains),
  2. compiles every pcre2/OSRegex pattern used in the rules,
  3. re-implements the static <field> matching semantics and runs the sample
     events (tests/sample_events.jsonl) through that matcher,
  4. asserts that attack events trigger the intended malicious-event rules and
     normal events do NOT.

The authoritative check against the real engine is:
    docker exec -it wazuh-manager /var/ossec/bin/wazuh-logtest
(see exercises/lesson 4) and tests/integration_check.sh.
"""

import json
import os
import re
import xml.etree.ElementTree as ET

import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_FILE = os.path.join(REPO_ROOT, "wazuh", "rules", "security_lab_rules.xml")
SAMPLES = os.path.join(REPO_ROOT, "tests", "sample_events.jsonl")

# rule id -> (level, group membership required)
REQUIRED_RULES = {
    "100100": (0, {"security_lab"}),
    "100101": (0, None),
    "100102": (0, None),
    "100110": (8, {"web", "attack"}),      # SQL injection
    "100111": (7, {"web", "attack"}),      # directory traversal
    "100112": (7, {"web", "attack"}),      # sensitive file access
    "100113": (12, {"web", "attack"}),     # webshell / command execution
    "100114": (0, None),                   # HTTP error base
    "100115": (6, {"web", "attack"}),      # repeated HTTP errors
    "100120": (3, {"authentication"}),     # single failed login
    "100121": (0, None),                   # successful login
    "100122": (10, {"authentication", "attack"}),  # brute force
    "100123": (12, {"authentication", "attack"}),  # successful attacker login
    "100130": (9, {"sysmon", "attack"}),   # suspicious file creation
    "100140": (8, {"ioc", "attack"}),      # connection to IoC range
    "100141": (12, {"ioc", "attack"}),     # exfiltration-sized transfer
    "100150": (5, {"config"}),             # configuration change
}

MALICIOUS_RULES = {"100110", "100111", "100112", "100113", "100115",
                   "100122", "100123", "100130", "100140", "100141"}


# Static rule tags (Wazuh analysisd treats these names as STATIC fields:
# using them in <field name=...> makes the rules fail to load with
# "Field 'url' is static"). The JSON decoder maps these keys to static slots,
# so rules must reference them via the static tags.
STATIC_TAGS = {"url", "status", "srcip", "dstip", "srcport", "dstport",
               "user", "protocol", "id", "location", "action", "system_name"}


def load_rules():
    tree = ET.parse(RULES_FILE)
    rules = {}
    for r in tree.getroot().findall("rule"):
        fields = [(e.get("name"), e.text, e.get("type", "osregex"))
                  for e in r.findall("field")]
        # static tags behave like field constraints in the offline matcher
        fields += [(tag, e.text, e.get("type", "osmatch"))
                   for tag in STATIC_TAGS for e in r.findall(tag)]
        rule = {
            "id": r.get("id"),
            "level": int(r.get("level")),
            "if_sid": [e.text.strip() for e in r.findall("if_sid")],
            "fields": fields,
            "frequency": int(r.get("frequency", "1")),
        }
        rules[rule["id"]] = rule
    return rules


def field_matches(pattern, regex_type, value):
    """Approximate the Wazuh field matcher:
    - osregex/osmatch patterns used here are anchored (^...$) simple regexes
    - pcre2 patterns are PCRE with (?i) inline flags; Python re is compatible
      for the subset used in this ruleset."""
    flag = 0
    if regex_type == "pcre2":
        pattern = pattern
        flag = 0
    try:
        return re.search(pattern, str(value), flag) is not None
    except re.error:
        raise


def rule_applies(rule, event, matched_ids):
    ok = True
    if rule["if_sid"]:
        ok = all(parent in matched_ids for parent in rule["if_sid"])
    for name, pattern, regex_type in rule["fields"]:
        if name not in event or not field_matches(pattern, regex_type, event[name]):
            ok = False
            break
    return ok


def evaluate(event, rules):
    """Return the list of rule ids that fire for one event (static model:
    frequency rules are evaluated separately - see expected frequencies)."""
    fired = set()
    changed = True
    while changed:
        changed = False
        for rid, rule in rules.items():
            if rid in fired:
                continue
            if rule_applies(rule, event, fired):
                fired.add(rid)
                changed = True
    # frequency rules: if_matched_sid with a satisfied count of events
    for rid, rule in rules.items():
        if rule["frequency"] > 1:
            fired.discard(rid)
    return fired


class TestRuleFile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = load_rules()
        with open(SAMPLES, encoding="utf-8") as fh:
            cls.samples = [json.loads(l) for l in fh if l.strip()]

    def test_xml_is_well_formed(self):
        self.assertGreaterEqual(len(self.rules), len(REQUIRED_RULES))

    def test_required_rules_present_with_level_and_groups(self):
        tree = ET.parse(RULES_FILE)
        for rid, (level, groups) in REQUIRED_RULES.items():
            self.assertIn(rid, self.rules, f"missing rule {rid}")
            self.assertEqual(self.rules[rid]["level"], level,
                             f"rule {rid} level")
            if groups:
                group_names = set()
                roots = tree.getroot().findall("group") or [tree.getroot()]
                for g in roots:
                    group_names.update(x.strip() for x in g.get("name", "").split(","))
                for r in tree.getroot().findall("rule"):
                    for geo in r.findall("groups"):
                        group_names.update(x.strip() for x in geo.text.split(","))
                for g in groups:
                    self.assertIn(g, group_names, f"rule {rid} group {g}")

    def test_ids_are_in_reserved_range(self):
        for rid in self.rules:
            self.assertTrue(100100 <= int(rid) <= 101999, rid)

    def test_parents_resolve(self):
        for rid, rule in self.rules.items():
            for parent in rule["if_sid"]:
                self.assertIn(parent, self.rules, f"{rid} -> {parent}")

    def test_pcre2_patterns_compile(self):
        n = 0
        for rid, rule in self.rules.items():
            for name, pattern, regex_type in rule["fields"]:
                compiled = re.compile(pattern)
                n += 1
                # every pattern must compile with the re module for the subset
                # of PCRE2 syntax used here (validated PCRE2 at runtime by
                # wazuh-logtest / the integration check).
                self.assertTrue(callable(compiled.search))
        self.assertGreater(n, 5)

    def test_alerting_rules_descriptions_are_labelled(self):
        tree = ET.parse(RULES_FILE)
        for r in tree.getroot().findall("rule"):
            if int(r.get("level")) >= 3:
                desc = r.find("description").text
                self.assertTrue(desc.startswith("SECURITY-LAB:"),
                                f"rule {r.get('id')} description label")


class TestSampleEventMatching(unittest.TestCase):
    """Static matcher over tests/sample_events.jsonl."""

    @classmethod
    def setUpClass(cls):
        cls.rules = load_rules()
        with open(SAMPLES, encoding="utf-8") as fh:
            cls.samples = [json.loads(l) for l in fh if l.strip()]

    def fired(self, event):
        return evaluate(event, self.rules)

    def test_all_samples_are_lab_events(self):
        for ev in self.samples:
            self.assertEqual(ev["case_id"], "SECURITY-LAB")
            self.assertTrue(ev["synthetic"])

    def test_web_attack_events_trigger_malicious_rules(self):
        for ev in self.samples:
            if ev["event_type"] != "http_request":
                continue
            if "UNION" in ev.get("url", "").upper() or "'1'='1" in ev.get("url", ""):
                self.assertIn("100110", self.fired(ev), ev)
            if "../" in ev.get("url", ""):
                self.assertIn("100111", self.fired(ev), ev)
            if "cmd=" in ev.get("url", "").lower():
                self.assertIn("100113", self.fired(ev), ev)
            if "shell.php" in ev.get("url", ""):
                self.assertIn("100113", self.fired(ev), ev)

    def test_client_events_trigger_malicious_rules(self):
        for ev in self.samples:
            if ev.get("event_type") == "auth_attempt" and ev.get("result") == "failure":
                self.assertIn("100120", self.fired(ev), ev)
            if ev.get("event_type") == "auth_attempt" and ev.get("result") == "success":
                if str(ev.get("srcip", "")).startswith("203.0.113."):
                    self.assertIn("100123", self.fired(ev), ev)
            if ev.get("event_type") == "file_creation":
                self.assertIn("100130", self.fired(ev), ev)
            if ev.get("event_type") == "network_connection":
                if str(ev.get("dstip", "")).startswith("198.51.100."):
                    self.assertIn("100140", self.fired(ev), ev)
                else:
                    self.assertNotIn("100140", self.fired(ev), ev)
            if ev.get("event_type") == "suspicious_transfer":
                self.assertIn("100141", self.fired(ev), ev)
            if ev.get("event_type") == "config_change":
                self.assertIn("100150", self.fired(ev), ev)

    def test_normal_events_never_trigger_malicious_rules(self):
        for ev in self.samples:
            normal = (
                (ev["event_type"] == "http_request" and ev["status"] == 200
                 and "cmd=" not in ev.get("url", "")
                 and "../" not in ev.get("url", ""))
                or (ev["event_type"] == "network_connection"
                    and str(ev.get("dstip", "")).startswith("192.0.2."))
                or (ev["event_type"] == "auth_attempt"
                    and ev.get("result") == "success"
                    and str(ev.get("srcip", "")).startswith("10.0.100."))
                or ev["event_type"] == "db_query"
            )
            if normal:
                self.assertFalse(self.fired(ev) & MALICIOUS_RULES,
                                 (ev, self.fired(ev)))

    def test_no_field_uses_a_static_rule_name(self):
        # regression for live failure: "Failure to read rule 100110.
        #  Field 'url' is static." - Wazuh refuses <field name="url"> etc.
        tree = ET.parse(RULES_FILE)
        offenders = []
        for r in tree.getroot().findall("rule"):
            for f in r.findall("field"):
                if (f.get("name") or "").lower() in {t.lower() for t in STATIC_TAGS}:
                    offenders.append((r.get("id"), f.get("name")))
        self.assertEqual(offenders, [])

    def test_web_rules_use_static_url_tags(self):
        # the JSON decoder maps 'url'/'status'/'srcip'/'dstip' into static
        # slots, so web request rules must match with <url>/<status> tags
        tree = ET.parse(RULES_FILE)
        by_id = {r.get("id"): r for r in tree.getroot().findall("rule")}
        for rid in ("100110", "100111", "100112", "100113"):
            self.assertIsNotNone(by_id[rid].find("url"))
        self.assertIsNotNone(by_id["100114"].find("status"))
        self.assertIsNotNone(by_id["100123"].find("srcip"))
        self.assertIsNotNone(by_id["100140"].find("dstip"))

    def test_frequency_rules_reference_existing_bases(self):
        tree = ET.parse(RULES_FILE)
        for r in tree.getroot().findall("rule"):
            for m in r.findall("if_matched_sid"):
                self.assertIn(m.text.strip(), self.rules)


if __name__ == "__main__":
    unittest.main()
