# Wazuh Security Lab

Et komplet, selvstændigt Docker-baseret cybersikkerhedslaboratorium med
[Wazuh](https://wazuh.com) til undervisning på bachelor-niveau. Laboratoriet
simulerer en lille virksomhed med **fem overvågede Linux-endpoints**, hvor to
er kompliante og tre indeholder simulerede sikkerhedsproblemer.

- **Wazuh 4.14.10** (manager, indexer, dashboard – pinlet version)
- Ét fælles endpoint-image med en **ægte Wazuh-agent** pr. endpoint
- Syntetisk telemetri fra en Python-simuleringsmotor (JSON-log)
- **SCA** (custom undervisningsbaseline), **FIM** (filintegritet) og **custom
  detektionsregler** (SQLi, traversal, brute force, eksfiltrering m.m.)
- Fem lektioner à 45 min + lærervejledning på dansk (`exercises/`)
- Kører 100 % lokalt – ingen cloud, ingen VM'er; dashboardet er kun bundet til
  127.0.0.1

> Alt indhold i laboratoriet er syntetisk og tydeligt mærket
> (`case_id: SECURITY-LAB`, `synthetic: true`). Der medfølger ingen malware,
> ingen ægte eksfiltrering og ingen offentligt eksponerede services.

## Indholdsfortegnelse
1. [Arkitektur](#1-arkitektur)
2. [Forudsætninger og installation](#2-forudsætninger-og-installation)
3. [Start laboratoriet](#3-start-laboratoriet)
4. [Dashboard-adgang og login](#4-dashboard-adgang-og-login)
5. [Verificér de fem agenter](#5-verificér-de-fem-agenter)
6. [Scenarier](#6-scenarier)
7. [Stop, nulstil og oprydning](#7-stop-nulstil-og-oprydning)
8. [Øvelser og undervisningsmateriale](#8-øvelser-og-undervisningsmateriale)
9. [Test og verifikation](#9-test-og-verifikation)
10. [Fejlfinding](#10-fejlfinding)
11. [Sikkerhedsafgrænsninger](#11-sikkerhedsafgrænsninger)
12. [Mappestruktur](#12-mappestruktur)
13. [Licens](#13-licens)

---

## 1. Arkitektur

Otte langkørende containere på ét dedikeret Docker-netværk
(`wazuh-security-lab-net`):

| Container | Billede | rolle |
|---|---|---|
| `wazuh-manager` | `wazuh/wazuh-manager:4.14.10` | regelfortolkning, agent-tilmelding (authd:1515), API (55000, kun internt) |
| `wazuh-indexer` | `wazuh/wazuh-indexer:4.14.10` | Wazuh-index (OpenSearch), ingen offentliggjorte porte |
| `wazuh-dashboard` | `wazuh/wazuh-dashboard:4.14.10` | web-UI, offentliggjort **kun på 127.0.0.1:8443** |
| `web-safe` | lokalt bygd (`endpoints/`) | kompliant webserver |
| `db-safe` | lokalt bygd | kompliant databaseserver |
| `legacy-web` | lokalt bygd | fejlkonfigureret (3 problemer + FIM-scenarie) |
| `web-attack` | lokalt bygd | modtager simuleret webangreb |
| `client-01` | lokalt bygd | simuleret kompromitteret arbejdsstation |

Alle fem endpoints bruger **samme image** (Debian slim + Wazuh-agent
4.14.10 + Python-simuleringsmotor). Endpoint-adfærden styres af
`ENDPOINT_NAME`/`LAB_PROFILE`. Hver agent har en egen volumen til
`/var/ossec/etc`, så agent-identiteten overlever genstart (ingen dublet-agenter).

Endpoint-scenarier:

| Endpoint | Rolige hændelser | Sikkerhedsproblemer |
|---|---|---|
| `web-safe` | HTTP 200-browsing | ingen (SCA 5/5) |
| `db-safe` | db-query + hvislogin | ingen (SCA 5/5) |
| `legacy-web` | HTTP 200-browsing | debug=true, anonym adgang, chmod 666, uautoriseret filændring |
| `web-attack` | HTTP 200-browsing | SQLi, traversal, scanning, webshell-kompromittering (ved aktivering) |
| `client-01` | login + browsertrafik | brute force, persistence-filer, beaconing, 8,5 MB "eksfiltrering" (ved aktivering) |

## 2. Forudsætninger og installation

| Komponent | Minimum | Bemærkning |
|---|---|---|
| CPU | 4 kerner | 5 er fint; Apple Silicon (arm64) er fuldt understøttet – alle officielle Wazuh-billeder findes som linux/amd64 **og** linux/arm64 (verificeret mod Docker Hub for 4.14.10) |
| RAM | 8 GB (16 GB anbefalet) | indexer kører her med -Xmx512m for at passe til undervisningsmaskiner |
| Disk | ~10 GB | billeder + Wazuh-data |
| OS | Windows x86-64, Linux x86-64, macOS Apple Silicon | Docker Desktop / Docker Engine 20.10+ med Compose v2 |
| Python | 3.8+ | kun til testpakken |

Installation:
- **Windows/macOS:** installer [Docker Desktop](https://www.docker.com/products/docker-desktop/).
- **Linux:** installer [Docker Engine](https://docs.docker.com/engine/install/) + compose-plugin.
- Linux ekstra: `sudo sysctl -w vm.max_map_count=262144` (indexer kræver det;
  `lab.sh up` advarer automatisk, hvis værdien er for lav).

Internetadgang er kun nødvendigt ved første `./lab.sh up` (image-download og
certifikatgenerering); alle scenarier kører derefter offline.

## 3. Start laboratoriet

```bash
git clone <repo-url> wazuh-security-lab
cd wazuh-security-lab
./lab.sh up
```

`lab.sh up` gør følgende automatisk:
1. kopierer `.env.example` → `.env` (trænings-defaults)
2. genererer lokale TLS-certifikater med den officielle
   `wazuh/wazuh-certs-generator:0.0.5` (én gang; gemmes i
   `wazuh/certs/wazuh_indexer_ssl_certs/`, git-ignoreret)
3. bygger endpoint-image og starter alle otte containere
4. venter på health (første start: 2–5 minutter) og udskriver login-oplysninger

## 4. Dashboard-adgang og login

- URL: **https://localhost:8443** (selv-signeret certifikat – acceptér i
  browseren; `wazuh/certs/wazuh_indexer_ssl_certs/root-ca.pem` kan importeres)
- Brugernavn/adgangskode: `admin` / værdien af `INDEXER_PASSWORD` i `.env`
  (default `SecretPassword`, som følger det officielle Wazuh Docker-billede).

Alle login-oplysninger udskrives også af:

```bash
./lab.sh status
```

API-adgang (avanceret): managerens API er kun tilgængelig inde i
Docker-netværket – brug fx
`docker compose exec wazuh-manager curl -sk -u 'wazuh-wui:<API_PASSWORD>' https://localhost:55000/agents?agents_list=list`.

## 5. Verificér de fem agenter

```bash
./lab.sh status          # containere + "N active agents (expected 5)"
```

I dashboardet: **Endpoints → Oversigt**. Forventet: fem agenter (`web-safe`,
`db-safe`, `legacy-web`, `web-attack`, `client-01`), alle med status `Active`.

## 6. Scenarier

```bash
./lab.sh scenarios                 # oversigt
./lab.sh scenario normal           # normale hændelser på alle 5 endpoints
./lab.sh scenario misconfiguration # 3 konfigurationsproblemer + FIM (legacy-web)
./lab.sh scenario web-attack       # SQLi, traversal, scanning, webshell (web-attack)
./lab.sh scenario compromised-client  # brute force, persistence, eksfiltrering (client-01)
```

Alarmerne vises i dashboardet under **Sikkerhedsbegivenheder** inden for ca.
et minut. Alle lab-alarmer er mærket med beskedpræfikset `SECURITY-LAB:` og
hændelsesfelterne `case_id=SECURITY-LAB`, `synthetic=true`.

Vigtige regel-ID'er: SQLi **100110**, traversal **100111/100112**, webshell
**100113**, HTTP-fejl-burst **100115**, fejlede logins **100120/100122**,
angriber-login **100123**, mistænkelig filoprettelse **100130**,
IoC-forbindelse **100140**, eksfiltrering **100141**, konfigurationsændring
**100150**. SCA-kontroller: 10100–10104 (policy: `security_lab_baseline`).

Simulering direkte i en container (deterministisk med `--seed`):

```bash
docker compose exec web-attack python3 /opt/lab/simulate.py web-attack --seed 42
docker compose exec client-01  python3 /opt/lab/simulate.py compromised-client --seed 42
```

## 7. Stop, nulstil og oprydning

```bash
./lab.sh down          # stop miljøet; Wazuh-data bevares i volumes
./lab.sh reset         # nulstil scenariotilstand på endpoints (ikke-destruktiv)
./lab.sh reset --volumes  # DESTRUKTIV: sletter ALLE Wazuh-data (kræver 'yes')
```

`reset` gendabler baselines (herunder legacy-webs fejlkonfiguration – det er
meningen), fjerner persistence-artefakter og rydder hændelsesloggen.
`reset --volumes` fjerner også certifikater, alerts og agentnøgler – bruges til
et totalfrisk semester-start.

## 8. Øvelser og undervisningsmateriale

- `exercises/student.md` – fem lektioner à ca. 45 minutter (dansk):
  1. Oplev miljøet
  2. Sikkerhedsbaseline (SCA) og FIM
  3. Threat hunting og IoCs
  4. Detektionsengineering (wazuh-logtest)
  5. Incident response (rapport)
- `exercises/teacher.md` – lærervejledning med forberedelse, ressourceforbrug,
  bevidste fejlkonfigurationer, forventede alarmer, svar på spørgsmål og
  bedømmelsesforslag.

## 9. Test og verifikation

Offline-test (kræver kun Python):

```bash
./lab.sh test
# eller direkte:
cd tests && python3 -m unittest discover -p 'test_*.py' -v
```

Dækkер: JSON-skema og determinisme i simuleringsmotoren, at normal aktivitet
ikke indeholder angrebsindikatorer, regel-XML (ID/level/grupper, PCRE-mønstre,
`wazuh-logtest`-prøvehændelser), compose-strukturens sikkerhedsegenskaber
(ingen endpoint-porte, localhost-dashboard, persistensvolumener) samt
TIP-baseline forventede SCA-resultater.

Med kørende lab (kræver Docker):

```bash
bash tests/smoke-test.sh        # config + build + 8 healthy + 5 agenter
./lab.sh verify                 # fuld 18-punkts integrationscheck
```

Integrationschecken spørger den **ægte Wazuh-API og -index** (agenter, SCA-
resultater, alarmer), inkl. remediering, genstart-stabilitet og
agent-identitetsstabilitet. Status for den aktuelle udgivelse findes i
`docs/verification.md`.

## 10. Fejlfinding

| Problem | Løsning |
|---|---|
| `wazuh-indexer` genstarter / "max virtual memory areas" | Linux: `sudo sysctl -w vm.max_map_count=262144` |
| Dashboard utilgængelig efter 5+ min | `docker compose ps` + `./lab.sh logs wazuh-dashboard`; indexeren skal være `healthy` først |
| Agent viser `Disconnected` | `./lab.sh logs <endpoint>`; manageren skal være `healthy` (entrypoint prøver tilmelding igen hvert 5. sek.) |
| "Mere end 5 agenter" | fjern dublet-agenten i dashboardet eller kør `./lab.sh reset --volumes` |
| Port 8443 er optaget | sæt `DASHBOARD_PORT=...` i `.env` og `docker compose up -d` |
| Certifikat-/TLS-fejl | slet `wazuh/certs/wazuh_indexer_ssl_certs/` og kør `./lab.sh up` igen |
| Ingen alarmer efter scenario | vent 1–2 min; `docker compose exec <endpoint> tail -5 /var/log/security-lab/events.json`; tjek at agenten er aktiv |
| **Apple Silicon: wazuh-manager crasher med `Illegal instruction`** | Faktisk fejl: `create_user.py: Illegal instruction`. Årsag: officielle arm64-billeder er bygget til Graviton-klassens CPU'er (bruger SVE, som Apple Silicon ikke implementerer). Løsning: 1) aktivér "Use Rosetta for x86_64/amd64 emulation on Apple silicon" i Docker Desktop (Settings → General), 2) sæt `WAZUH_PLATFORM=linux/amd64` i `.env`, 3) `docker compose down -v` og `./lab.sh up` igen |
| Regler ændres ikke | regelfilen mountes til manageren ved hver start (`wazuh-config-mount`); kør `docker compose restart wazuh-manager` |

## 11. Sikkerhedsafgrænsninger

- Dashboardet er kun bundet til **127.0.0.1**; ingen andre porte er
  offentliggjorte (API/indexer/agenttrafik er kun på det interne netværk).
- Endpoint-containere lytter ikke på nogen porte; al "trafik" er simulerede
  loglinjer.
- Eksterne aktører bruger udelukkende RFC 5737-reserverede adresser
  (192.0.2.x, 198.51.100.x, 203.0.113.x).
- Al telemetri er mærket `synthetic: true`; SCA-policyen er en
  *undervisnings*-baseline og beviser ikke CIS-/regulatory compliance.
- Wazuh's indbyggede vulnerability-detektion (CVE-feed) observerer kun
  pakkeversioner; ingen lab-scenarie-genererede fund må fremstilles som
  CVE-resultater.

## 12. Mappestruktur

```text
wazuh-security-lab/
├── compose.yaml              # 8 containere (Wazuh + 5 endpoints)
├── lab.sh                    # én-kommando-styring (up/status/scenario/...)
├── Makefile                  # make-up/status/scenario-*/test
├── .env.example              # trænings-defaults (kopieres til .env)
├── wazuh/
│   ├── manager/ossec.conf    # manager-konfiguration (officielt Wazuh-layout)
│   ├── rules/security_lab_rules.xml   # custom detektionsregler (100100-100150)
│   ├── indexer/wazuh-indexer.yml
│   ├── dashboard/            # opensearch_dashboards.yml + wazuh.yml (API-login)
│   └── certs/                # certifikatgenerator (output er git-ignoreret)
├── endpoints/
│   ├── Dockerfile            # fælles image: debian slim + wazuh-agent + simulator
│   ├── entrypoint.sh         # tilmelding, agentstart, simuleringsdaemon
│   ├── ossec.conf            # agent-konfiguration (logcollector/FIM/SCA)
│   ├── simulate.py           # simuleringsmotor (normal/misconfiguration/...)
│   ├── sca/security_lab_baseline.yml   # custom SCA-policy (5 kontroller)
│   └── baselines/            # per-endpoint app-konfiguration
├── scenarios/                # normal, misconfiguration, web_attack, compromised_client
├── exercises/                # student.md + teacher.md (dansk)
├── tests/                    # unit-tests, regeltest, smoke + integrationscheck
└── docs/verification.md      # teststatus for udgivelsen
```

## 13. Licens

GPLv2 (se `LICENSE`). Wazuh-konfigurationsfiler og certifikatværktøj er
afledt af det officielle [wazuh-docker](https://github.com/wazuh/wazuh-docker)
 repositorium (Wazuh Inc., GPLv2). Wazuh er (C) Wazuh Inc.
