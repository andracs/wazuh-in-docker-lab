# Verifikationsstatus for denne udgivelse

This document records what has actually been verified for this release. The
lab was developed in a sandbox **without a Docker daemon** (unprivileged
user, no container runtime). By project rules, integration results that
could not be executed are documented as **UNVERIFIED** rather than claimed
as passing.

## Verified offline (actually executed in the release sandbox)

```
cd tests && python3 -m unittest discover -p 'test_*.py' -v
Ran 41 tests ... OK
```

| Area | Verification | Result |
|---|---|---|
| Simulation engine, 5 profiles | `tests/test_simulation.py` (13 tests): JSON schema, sequence, seeds/determinism, profile guard rails, reset idempotency, artifact create/remove | **PASS (41/41 overall)** |
| Normal activity is clean | normal events for all 5 endpoints checked for absence of attacker IPs, SQLi, traversal, webshell patterns | **PASS** |
| Custom rules XML | `tests/test_rules.py` (11 tests): well-formed XML, ids 100100–100150 present with intended levels/groups, all PCRE patterns compile, `wazuh-logtest`-ready sample events match intended rule ids, normal events never match malicious rules | **PASS** |
| Rules fixed during testing | offline matcher found and fixed two real defects (SQLi `'1'='1` URL matched nothing; `suspicious_transfer` missing from base rule 100102) | **PASS after fix** |
| SCA policy + baselines | `tests/test_compose.py`: policy parses, 5 checks with remediation text, compliant endpoints evaluate 5/5, legacy-web fails exactly 10100/10101/10102 | **PASS** |
| compose.yaml structure | exactly the 8 services, no endpoint ports, dashboard on 127.0.0.1 only, healthchecks, restart policies, mem limits, per-endpoint `/var/ossec/etc` volumes, dedicated network | **PASS** |
| Script syntax | `bash -n lab.sh tests/smoke-test.sh tests/integration_check.sh` | **PASS** |
| Official images multi-arch | Docker Hub manifest list for 4.14.10 checked: manager/indexer/dashboard (+agent) all provide linux/amd64 and linux/arm64 | **VERIFIED** |

## UNVERIFIED in this environment (requires a Docker daemon)

These are implemented and scripted, but were **not executed** here because the
sandbox has no Docker daemon. Run them on a Docker-capable machine:

```
docker compose config            # 1. compose validation by Docker itself
./lab.sh up                      # 2-4. build, 8 containers, health
bash tests/smoke-test.sh          # 5. smoke
./lab.sh verify                  # 6-18. full integration checklist
```

Specifically the following acceptance points remain runtime-verified only by
the included `tests/integration_check.sh`:

1. Endpoint image build (apt pin `wazuh-agent=4.14.10-1` resolves).
2. All 8 containers start and reach `healthy`.
3. Five agents register through wazuh-authd without duplicates.
4. JSON events are ingested (alerts in `wazuh-alerts-*`).
5. SCA results in the live dashboard (legacy-web 3 fails; others 5/5).
6. FIM alert on `/etc/labapp/app.conf` modification.
7. Rule firing 100110/100111/100112/100113/100115/100120/100122/100123/
   100130/100140/100141 against the live engine.
8. Remediation flips SCA to 5/5; identity stability across restarts; full
   stop/start cycle.

## Defects found and fixed during live deployment (Apple Silicon M4 Max)

Two real defects were discovered on a live deployment and fixed + covered by
regression tests:

1. `Syntax error on tag 'event_type' in rule 100102` -> manager exited at
   startup. Cause: regex alternation (`|`) used in a plain `<field>` pattern;
   Wazuh's default OS_Regex engine does not support it. Fix: `type="pcre2"`.
   Regression test: `test_rule_fields_do_not_use_osregex_alternation`.
2. Indexer REST API returned `Unauthorized` for `admin:SecretPassword`.
   Cause: `internal_users.yml` (the officially shipped file whose admin hash
   matches `SecretPassword`) was not mounted into wazuh-indexer, so the image
   kept the OpenSearch *demo* internal users (`admin`/`admin`). Fix: mount
   `wazuh/indexer/internal_users.yml` to
   `/usr/share/wazuh-indexer/config/opensearch-security/internal_users.yml`.
   Regression test: `test_indexer_mounts_internal_users`.
   Note: applying this fix requires recreating the indexer volume
   (`docker compose down -v`), since the security index caches the demo
   credentials after first initialization.

3. `Failure to read rule 100110. Field 'url' is static.` -> analysisd exited
   and ALL manager daemons were down. Cause: matching rules used
   `<field name="url|status|srcip|dstip">`; those names are STATIC Wazuh rule
   fields (the JSON decoder maps them into static slots), so they must be
   referenced with the static tags `<url>`, `<status>`, `<srcip>`, `<dstip>`.
   Fix applied to rules 100110-100114, 100123, 100140; regression tests:
   `test_no_field_uses_a_static_rule_name`,
   `test_web_rules_use_static_url_tags` (offline matcher extended to
   emulate the static tags).

## Known risks to watch on first real run

- `wazuh-agent` Debian package name/version pinning (`4.14.10-1`) – if the
  apt repository changes suffixes, adjust `WAZUH_APT_VERSION` in
  `endpoints/Dockerfile`.
- Ingestion delay for frequency rules: `100115` needs 8 HTTP errors within
  180 s and `100122` needs 8 failed logins within 120 s – the scenarios emit
  them back-to-back, so this should hold comfortably.
- Very slow hosts: the first `./lab.sh up` may need more than the 7-minute
  wait loop; rerun `./lab.sh status` until healthy.
- Apple Silicon (confirmed on M4 Max, native linux/arm64, image 4.14.10):
  the wazuh-manager container crashes with `Illegal instruction` in
  `/var/ossec/framework/python/bin/python3 create_user.py` during init.
  The bundled binaries in the official arm64 image target Graviton-class
  CPUs and use instructions Apple Silicon does not implement. Workaround
  implemented and documented: `WAZUH_PLATFORM=linux/amd64` in `.env`
  (exported as `DOCKER_DEFAULT_PLATFORM` by lab.sh) + Rosetta emulation in
  Docker Desktop. The native-arm64 path is therefore UNVERIFIED on Apple
  Silicon; use the amd64/Rosetta path.
