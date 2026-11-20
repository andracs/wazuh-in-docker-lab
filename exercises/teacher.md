# Wazuh Security Lab – lærervejledning (dansk)

Formålet med laboratoriet er, at bachelorstuderende lærer at opdage,
undersøge, korrelere og remediere sikkerhedsproblemer med Wazuh i et lokalt
Docker-miljø. Laboratoriet er fuldt syntetisk: alle "angreb" er genererede
log-hændelser og harmløse filer. Ingen malware, ingen ægte
legitimationsafhentning og ingen ægte dataforsendelse.

Læs `README.md` først for opsætningsdetaljer. Elevmaterialet ligger i
`exercises/student.md` med fem lektioner à ca. 45 min.

---

## 1. Forberedelse (firskæringsvejledning)

### Nødvendig software
| Software | Krav |
|---|---|
| Docker Desktop (macOS/Windows) eller Docker Engine 20.10+ | + Compose v2-plugin |
| Python | 3.8+ (til testpakken) |
| Browser | moderna browser (selvsigneret TLS accepteres) |
| Git | til at klone repositoriet |

### Hardware (anbefalet)
- 4+ CPU-kerner (Apple Silicon M1/M2/M3 understøttes – alle Wazuh-billeder
  findes som linux/arm64)
- 16 GB RAM anbefalet (min. 8 GB, indexing kræver ~1 GB alene)
- ~10 GB ledig diskplads (billeder + Wazuh-data)

### Opsætningstrin til underviser
```bash
git clone <repo-url> wazuh-security-lab && cd wazuh-security-lab
./lab.sh up            # kopiér .env, generer certifikater, bygg/start alting
./lab.sh status        # vis 8 containere + 5 agenter + login
bash tests/smoke-test.sh   # hurtigoversigt (konfig, bygg, sundhed, agenter)
```
Ved semestrestart/afdelings-eksamener: `./lab.sh reset --volumes` giver et
helt frisk Wazuh (kræver interaktiv bekræftelse – fjerner ALLE persistente
data inkl. alerts).

### Linux-hosts
`sudo sysctl -w vm.max_map_count=262144` (indexer fejler ellers sandsynligvis).
`lab.sh up` advarer automatisk, hvis værdien er for lav.

### Forventet ressourcetræk efter opstart
| Komponent | Cirka forbrug |
|---|---|
| wazuh-indexer | 1,2-1,5 GB RAM |
| wazuh-manager | 0,4-0,8 GB RAM |
| wazuh-dashboard | 0,5-0,8 GB RAM |
| hver endpoint | 60-120 MB RAM |
| **I alt** | ca. 3,5-4,5 GB RAM |

### Introduktionsordliste til instrumentbrættet (kort til studerende)
- **Agent**: Wazuh-software på endpointet, sender logdata og FIM/SCA-resultater.
- **SCA**: konfigurationsvurdering på agenten (politik: `security_lab_baseline`).
- **FIM (syscheck)**: filintegritetsovervågning af `/etc/labapp`,
  `/home/devuser`, `/opt/lab/data`.
- **Regel/add-on**: reglen `security_lab_rules.xml` leverer alle
  alarms-beskeder med præfiks `SECURITY-LAB:`.

## 2. Læringsmål (kurselevel)
Efter de fem lektioner kan den studerende:
1. Betjene Wazuh-dashboardet og verificere agenttilstand.
2. Forklare og påvise virkemåden af SCA, FIM og logbaserede regler (og deres
   begrænsninger).
3. Udføre en struktureret hændelsesundersøgelse: bygge en tidslinje med IP'er,
   tidsstempler og regel-ID'er, adskille forsøg fra gennemført kompromittering.
4. Skrive og teste en detektionsregel mod syntetiske hændelser (logtest).
5. Skrive en prioriteret incident rapport med evidens, response-handlinger,
   remediation og verificering.

## 3. De fem endpoints

| Endpoint | Rolle | Scenarie | Forventet dashboard-resultat ved opstart |
|---|---|---|---|
| `web-safe` | compliant webserver | ingen | SCA 5/5, ingen lab-alarmer |
| `db-safe` | compliant databaseserver | ingen | SCA 5/5, ingen lab-alarmer |
| `legacy-web` | fejlkonfigureret | 3 misconfigurations + uautoriseret filændring | SCA 3 FAIL (10100,10101,10102) |
| `web-attack` | webserver | web-angrebsscenario (aktiveres) | ingen indtil aktivering |
| `client-01` | arbejdsstation | kompromitteret-klient-scenario (aktiveres) | ingen indtil aktivering |

## 4. Alle bevidste fejlkonfigurationer (transparens)

| # | Endpoint | Problem | Sådan simuleres | Sådan rettes |
|---|---|---|---|---|
| 1 | legacy-web | `debug=true` i `/etc/labapp/app.conf` | baseline-fil `endpoints/baselines/legacy-web.conf`; re-aktiveres med `./lab.sh scenario misconfiguration` | `sed -i 's/^debug=.*/debug=false/' /etc/labapp/app.conf` |
| 2 | legacy-web | `anonymous_access=true` | som ovenfor | `sed -i 's/^anonymous_access=.*/anonymous_access=false/' ...` |
| 3 | legacy-web | filtilladelser 0666 på `app.conf` | entrypoint + misconfiguration-scenario | `chmod 640 /etc/labapp/app.conf` |
| 4 | legacy-web | uautoriseret kommentar tilføjet (FIM) | `scenario misconfiguration` (appender `# hotfix ... unscheduled`) | rediger filen og fjern linjen |

Bemærk: **web-attack og client-01 er teknisk compliant ift. SCA - deres
problemer er hændelsesbaserede, ikke konfigurationsbaserede.**

## 5. Kortlægning: endpoint → problem → detektion → evidens → remediation

| Endpoint | Problem | Detektionsmekanisme | Forventet evidens | Remediation |
|---|---|---|---|---|
| legacy-web | Debug-tilstand slået til | SCA-kontrol 10100 | dashboard SCA: FAIL med remediation-forslag | `debug=false`, `docker compose restart legacy-web` |
| legacy-web | Anonym adgang | SCA-kontrol 10101 | som ovenfor | `anonymous_access=false` + genstart |
| legacy-web | Usikre filtilladelser (666) | SCA-kontrol 10102 + evt. FIM ved ændring | `stat -c %a` → 666; STATUS i `app.conf`-alarm | `chmod 640` + genstart (SCA scan-on-start) |
| legacy-web | Uautoriseret filændring | FIM/syscheck (realtime) | alarm `rule.groups:syscheck`, `syscheck.path=/etc/labapp/app.conf`, md5/sha-diff | fjern linjen; FIM-bekræftelse ved næste ændring |
| web-attack | SQLi-forsøg | lab-regel 100110 (niveau 8) | alerts med `data.url`-mønstre og `srcip=203.0.113.x` | inputvalidering/WAF uden for lab-scope |
| web-attack | Directory traversal | lab-regel 100111/100112 | url indeholder `../` eller `/etc/passwd` | PATH-håndtering i app |
| web-attack | Webshell-adgang (kompromittering) | lab-regel 100113 (niveau 12) | `url:/uploads/shell.php?cmd=...` 200-svar | blokér IP, fjern shell, geninstallér app |
| web-attack | Automatiseret scanning (404-burst) | lab-regel 100115 (niveau 6, freq 8/3min) | 8+ 4xx/5xx fra samme srcip | rate-limit/WAF |
| client-01 | SSH brute force (10 fejlede) | lab-regel 100120 (niveau 3) + 100122 (niveau 10, freq 8/2min) | auth_attempt failure × 10 fra 203.0.113.77 | blokér IP, force nøglebaseret login |
| client-01 | Succesfuld login fra angriber-IP | lab-regel 100123 (niveau 12) | auth_attempt success fra 203.0.113.77, user devuser | isolation, kontoskift, session-kill |
| client-01 | Persistence-artifacts (authorized_keys, skjult script) | FIM (nye filer) + lab-regel 100130 (niveau 9) | file_creation event + FIM added-alert; filindhold mærket "HARMLESS TRAINING ARTIFACT" | fjern filer (`simulate.py reset`), nulstil konti |
| client-01 | Beaconing til C2 | lab-regel 100140 (niveau 8) | network_connection → 198.51.100.50:8443 × 3 | netværksblokade, EDR |
| client-01 | Eksfiltrering i stor størrelse (8,5 MB) | lab-regel 100141 (niveau 12) | suspicious_transfer → 198.51.100.99:4444, `bytes=8500000`, `result=simulated` | luk forbindelser, DLP-analyse, password-rotation |

## 6. Hændelses-skema og adresser (til underviserens reference)

Alle hændelser er én-linjers JSON i `/var/log/security-lab/events.json` på
hvert endpoint, med felter: `timestamp, sequence, event_type, endpoint,
case_id("SECURITY-LAB"), synthetic(true)` + typespecifikke felter
(`srcip/dstip/user/method/url/status/bytes/protocol/result/evidence/...`).

Kun RFC 5737-reserverede adresser bruges for eksterne aktører:

| Rolle | Adresse/rækkevidde |
|---|---|
| Interne, normale klienter | 10.0.100.x |
| Normal internettrafik | 192.0.2.x (TEST-NET-1) |
| Angribere (web) | 203.0.113.10/.15/.66 (TEST-NET-3) |
| Brute force-kilde (klient) | 203.0.113.77 |
| C2/beacon | 198.51.100.50 |
| Eksfiltreringsmål | 198.51.100.99 (port 4444) |

## 7. Kommandoer til aktivering af scenarier (underviser/evaluering)

```bash
./lab.sh scenarios                       # oversigt
./lab.sh scenario normal                 # normale hændelser på ALLE endpoints
./lab.sh scenario misconfiguration       # kun legacy-web (3 problemer + FIM)
./lab.sh scenario web-attack             # kun web-attack
./lab.sh scenario compromised-client     # kun client-01

# direkte i en container (deterministisk med seed):
docker compose exec legacy-web  python3 /opt/lab/simulate.py misconfiguration --seed 42
docker compose exec web-attack   python3 /opt/lab/simulate.py web-attack --seed 42
docker compose exec client-01    python3 /opt/lab/simulate.py compromised-client --seed 42

./lab.sh scenario normal              # normal aktivitet alene giver ingen alarm
```

### Gendannels- og reset-kommandoer
```bash
docker compose exec client-01 python3 /opt/lab/simulate.py reset   # rens client
./lab.sh reset            # nulstil scenarier på alle endpoints (ikke-destruktiv)
./lab.sh down              # stop (data bevares i volumes)
./lab.sh reset --volumes   # DESTRUKTIV: alt Wazuh-data slettes (kræver 'yes')
```

## 8. Forventede alarmer efter scenarier (verifikations-tabel)

| Scenarie | Forventede regel-ID'er (niveau) |
|---|---|
| misconfiguration (legacy-web) | SCA 10100/10101/10102 FAIL; FIM-syscheck (filændring); lab-regel 100150 (niveau 5, config_change) |
| web-attack (web-attack) | 100110 (8) × 4, 100111 (7) × 3, 100112 (7, evt.), 100113 (12) × 4, 100115 (6, efter 8 fejl samme IP) |
| compromised-client (client-01) | 100120 (3) × 10, 100122 (10, efter 8 fejlede/2min), 100123 (12), 100130 (9) × 2, 100140 (8) × 3, 100141 (12); FIM: to nye filer i /home/devuser |
| normal (alle) | INGEN alarms ≥ level 3 fra reglerne 100110-100141/100150 |

Al ingestionstid: forvent 30-90 sekunder fra aktivering til dashboard
(manager + indexer + dashboards API).

## 9. Svar på undersøgelsesspørgsmål (pr. lektion)

### Lektion 1 –
1. Fem agenter: `web-safe, db-safe, legacy-web, web-attack, client-01`
   (ID 001-005, se mapning i dashboardet).
2. Ikkomp liant endpoint genkendes på SCA-symbol (rød/orange "shield");
   `legacy-web` har 3 fails.
3. 8 containere: manager+indexer+dashboard=3 Wazuh-infra + 5 endpoints
   (hver endpoint kører en real agent; dashboard viser kun endpoints der
   rapporterer, ikke manageren selv).
4. Inventar-forskelle er minimale (samme image); rollen findes i
   baseline-filens `endpoint_role` og i logmønstrene (db-query vs http).

### Lektion 2 –
1. 10100 (debug), 10101 (anonym adgang), 10102 (filtilladelser 0666).
2. Prioritering: anonym adgang (umiddelbar adgang) og derefter
   filtilladelser (muliggør flere ændringer af konfigurationen).
3. FIM viser filstien, tidsstempel og checksum-diff, men ikke *hvem/hvorfor*;
   det kræver fil-auditering (auditd) eller adgangsstyringslogging.
4. Verifikation: `docker compose exec legacy-web stat -c %a /etc/labapp/app.conf`
   → 640; SCA-dashboard viser 5/5 efter genstart (scan_on_start).
5. Agenten holder SCA-intervallet på 30 min; genstart trigge scan_on_start.

### Lektion 3 –
1. 203.0.113.10/15/66. Kompromitteringskilde: den IP der udnytter upload
   og derefter tilgår webshell (samme `srcip` i 100113-hændelserne).
2. Regel 100113 (webshell/adgang med `cmd=`) – eller 100123 for klienten.
   Forskellen på forsøg og gennemført: en successfuld (200) kommandoeksekvering.
3. Forventet rækkefølge: failures → success login → persistence-filer →
   beaconing → exfiltrering (tidsstempler i events.json / alert-felter).
4. Isoler først client-01 (bevis: bevaring af logs/FIM-billede før genstart);
   derefter web-attack (blokér IP, fjern webshell). Først derefter legacy-web
   (konfiguration).
5. Overførselsstørrelsen er et indikatium (kan være backup/legitimt); bevis
   kræver netværks- eller DLP-evidens.

### Lektion 4 –
1. `if_sid` hænger reglen til en forælder (fx 100101); gør at reglen kun
   evalueres for http_request-hændelser fra lab'et.
2. JSON-loggen parses af logcollectoren (log_format=json); felterne
   (<field name="url">...) matches mod de parsede felter.
3. `frequency=3` gør reglen følsomere (flere falske positiver); for 2-min-reglen
   er der større risiko for alert-flooding.
4. Basereglen 100100 kræver `case_id=SECURITY-LAB`, så ægte systemtelemetri
   (fx syslog) aldrig matcher elevreglerne.

### Lektion 5 –
1. Prioritering (forventet): (1) client-01-kompromittering – aktiv modtager
   af data, (2) web-shell-upload på web-attack, (3) legacy-web misconfig
   (ingen direkte udnyttelses-evidens endnu). Acceptér velbegrundede
   afvigelser.
2. Førstehandlinger: isolation (netværk), blokade af 203.0.113.x og
   198.51.100.x, fjern persistence, kontoskift af devuser, bevisfiksation.
3. Verificering uden at ødelægge beviser: kopiér loggene/eksportér alerts
   først (`docker compose exec client-01 cat /var/log/security-lab/events.json > evidens.json`)
   og gem dashboard-eksport af relevante alarmer, før der ændres noget.
4. Manglende evidens: netværkstrafik-indhold, filindhold,
   identitets-/proces-kontekst (auditd/EDR), historisk SCA.

## 10. Fejlsøgning (troubleshooting)

| Symptom | Årsag og løsning |
|---|---|
| `wazuh-indexer` restart-loops / `max virtual memory areas` | `vm.max_map_count` for lav på Linux: `sudo sysctl -w vm.max_map_count=262144` |
| Dashboard: "not ready yet" / side viser ingenting i > 5 min | Vent – indeks+manager starter sekventielt; tjek `docker compose ps`, `./lab.sh logs wazuh-dashboard` |
| Agent "Disconnected" i dashboardet | endpoint kunne ikke registrere sig; tjek `./lab.sh logs <endpoint>` og at `wazuh-manager` er `healthy` |
| Mere end 5 agenter | nogen har genskabt volumes forkert; kør `./lab.sh reset --volumes` (destruktivt) eller slet agenten i dashboardet |
| `certs`-fejl ved opstart | slet `wazuh/certs/wazuh_indexer_ssl_certs/` og kør `./lab.sh up` igen |
| Windows Docker Desktop: port 8443 optaget | `set DASHBOARD_PORT=...` i `.env` og `docker compose up -d` |
| Apple Silicon ekstrem langsom | Rosetta er ikke påkrævet (billeder er native arm64) – tjek at Docker Desktop har fået ≥ 4 GB RAM |
| Intet i Security events efter scenario | vent 1-2 minuts ingestion; tjek `docker compose exec <ep> tail -5 /var/log/security-lab/events.json` og at agenten er aktiv |
| `wazuh-logtest` findes ikke | stien er `/var/ossec/bin/wazuh-logtest` (i managercontaineren) |

## 11. Forslag til evaluering/bedømmelse

| Lektion | Aflevering | Bedømmelsesnøgler |
|---|---|---|
| 1 | endpoint-oversigt | alle 5 endpoints + agent-ID + baseline-status; korrekt brug af dashboard/CLI-bevis |
| 2 | fund + FIM-analyse + remediation | korrekt kontrol-ID'er; forklarer forskellen SCA vs FIM; remediation verificeret (frem/tilbage SCA + permissions) |
| 3 | tidslinje ≥ 4 hændelser | korrekte IP'er/rule-ID'er; adskiller forsøg vs. kompromittering (100113/100123) |
| 4 | virkende elevregel | reglen udløses kun af tilsigtet hændelse; bruger wazuh-logtest som bevis; refleterer over falske positiver |
| 5 | incident-rapport 1-2 sider | prioritering med begrundelse, response-handlinger, verificering, begrænsnings-diskussion (fx "FIM viser ikke hvem") |

Karaktérdforskelle: D: aflevering udfyldt; C: korrekt teknisk indhold;
B: selvstændig korrelation/tidslinje-bevis; A/A+B: original detektion eller
velbegrundet response/bevis på begrænsninger med
forbedringsforslag.

## 12. Hvad laboratoriet IKKE gør (vigtigt for korrekt undervisning)

- Ingen ægte sårbarheder udnyttes – alle angreb er syntetiske log-tekstdata
  mærket `case_id: SECURITY-LAB`, `synthetic: true`.
- Wazuh's CVE vulnerability-detektør rapporterer kun baseline-facts om
  pakkeversioner. Lab-baseline-resultater må aldrig fremstilles som
  "CIS-compliance" eller "reel sårbarhedsscanning".
- FIM og SCA er virkelige Wazuh-komponenter, men de vurderer en *simuleret*
  applikationskonfiguration (tommelfingerregel adskilles tydeligt i
  lektion 2/3-materialet).
- Der afholdes ingen netværksscanning, ingen udgående dataforbindelser fra
  scenarierne; alle eksterne adresser er RFC 5737-reserverede.
