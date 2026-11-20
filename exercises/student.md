# Wazuh Security Lab – elevøvelser (5 lektioner)

Dette dokument indeholder fem strukturerede lektioner à ca. 45 minutter til
Wazuh Security Lab. Laboratoriet kører lokalt med Docker og består af Wazuh
(manager, indexer, dashboard) samt fem overvågede Linux-endpoints:

| Endpoint    | Rolle                        | Status               |
|-------------|------------------------------|----------------------|
| `web-safe`  | compliant webserver           | OK                   |
| `db-safe`   | compliant databaseserver     | OK                   |
| `legacy-web`| forældet, fejlkonfigureret server | 3 konfigurationsproblemer |
| `web-attack`| webserver under angreb       | angreb simuleres     |
| `client-01` | arbejdsstation, muligvis kompromitteret | hændelse simuleres |

Alle hændelser i laboratoriet er **syntetiske** og tydeligt mærket med
`case_id: SECURITY-LAB`. Intet rigtig angreb finder sted, og ingen data
forlader din maskine.

**Forudsætninger:** gennemført `./lab.sh up` (se README.md) og adgang til
Wazuh-dashboardet på `https://localhost:8443` (login står i `.env` og udskrives
af `./lab.sh status`).

---

## Lektion 1 – Oplev miljøet (ca. 45 min)

### Læringsmål
- Starte et komplet Docker-baseret SIEM-laboratorium med én kommando.
- Navigere i Wazuh-dashboardet (Moduler, Endpoints, Sikkerhedsbegivenheder).
- Verificere, at fem agenter er registreret og tilsluttet.
- Bruge agentinventar til at beskrive hvert endpoints rolle og tilstand.
- Genkende laboratoriets baseline (hvad er "normalt" her?).

### Kommandoer
```bash
./lab.sh up        # starter miljøet (første gang tager 2-5 minutter)
./lab.sh status    # viser containere, agenter og login-oplysninger
```

### Trin i Wazuh-dashboardet
1. Åbn `https://localhost:8443` (godkend selv-signeret certifikat).
   Login: `admin` / adgangskoden fra `.env` (`INDEXER_PASSWORD`).
2. Gå til **Endpoints → Oversigt** (Agents overview). Notér:
   - Hvor mange agenter er aktive? (Forventet: 5, status `Active`.)
   - Klik på hver agent og find fanen **Konfiguration** (Configuration) og
     **Inventar** (Inventory). Hvilken OS-version og hvilke pakker er
     installeret? Hvorfor ser alle fem nogenlunde ens ud?
3. Åbn **Sikkerhedsbegivenheder** (Security events) under **Moduler** (Modules).
   Filtrér på `rule.groups: security_lab`. Med hvilke felter kan man se, at
   hændelserne er syntetiske (`case_id`, `synthetic`)? Klik på en hændelse og
     se JSON-felterne (fx `data.event_type`, `data.endpoint`).
4. Kig på **Systemstatistik / Health** for de tre Wazuh-komponenter
   (manager, indexer, dashboard) under Dashboard-oversigten.

### Undersøgelsesspørgsmål
1. Hvilke fem endpoints er tilsluttet, og hvilket ID har hver agent?
2. Hvordan ser du forskellen på et kompliant og et ikke-kompliant endpoint
   allerede i agentoversigten? (Tip: SCA-ikon/kolonne.)
3. Hvorfor er der seks "controllere" (manager + 5 agenter), men kun ét kernemiljø?
4. Ved hjælp af inventar-data: hvad er endpoint `client-01`s rolle sammenlignet
   med `db-safe`?

### Forventede observationer (uden alle svar)
- Alle fem agenter rapporterer `Active`.
- `legacy-web` har røde/orange markeringer under SCA; `web-safe` og `db-safe`
  ikke. Forklaringen findes i lektion 2.
- Sikkerhedsbegivenheder indeholder hændelser med `case_id: SECURITY-LAB`.

### Aflevering
Én side "Endpoint-oversigt": tabel med de fem endpoints, agent-ID, rolle,
baseline-status (grøn/rød) og en linje om, hvordan du verificerede
tilslutningen (kommando eller skærmbillede).

---

## Lektion 2 – Sikkerhedsbaseline og FIM (ca. 45 min)

### Læringsmål
- Forklare forskellen mellem SCA (konfigurationsvurdering), FIM
  (filintegritet) og logbaserede detektioner.
- Sammenligne SCA-fund fra laboratoriets egen baseline-policy.
- Udløse en overvåget filændring med vilje og analysere FIM-alarmen.
- Remediere mindst ét konfigurationsproblem og genkøre vurderingen.

### Baggrund
Denne varighed bruger laboratoriets egen lille SCA-policy
`security_lab_baseline` med fem kontroller (ID 10100–10104), der vurderer den
simulerede applikationskonfiguration `/etc/labapp/app.conf`:
debug deaktiveret, anonym adgang deaktiveret, sikre filtilladelser (maks 0640),
audit-logning aktiveret og begrænset administratoradgang.

> Bemærk: denne undervisningsbaseline er IKKE en CIS/DGDPR-compliancekontrol;
> at bestå den beviser kun, at labsimuleringen er konfigureret korrekt.

### Kommandoer
```bash
# aktiver fejlkonfigurationsscenariet på legacy-web (hvis ikke allerede vist):
./lab.sh scenario misconfiguration

# udløs en uautoriseret filændring manuelt (samme effekt):
docker compose exec legacy-web sh -c 'echo "# unauthorized hotfix" >> /etc/labapp/app.conf'

# inspicer filen og tilladelserne:
docker compose exec legacy-web sh -c 'ls -l /etc/labapp/app.conf && cat /etc/labapp/app.conf'

# remedier (øvelse):
docker compose exec legacy-web sh -c \
  "sed -i 's/^debug=.*/debug=false/; s/^anonymous_access=.*/anonymous_access=false/' /etc/labapp/app.conf && chmod 640 /etc/labapp/app.conf"

# genstart endpointet for at tvinge en SCA-skanning (scan_on_start):
docker compose restart legacy-web
```

### Trin i Wazuh-dashboardet
1. **Endpoints** → vælg `legacy-web` → **SCA (Security Configuration
   Assessment)** → åbn policy `security_lab_baseline`.
   Hvilke tre kontroller fejler (ID, titel, remediation)?
2. Sammenlign med `web-safe` og `db-safe`: består de 5/5?
3. Klik på en fejlende kontrol og læs **Remediation**-teksten. Udfør den.
4. Find FIM-alarmen: **Sikkerhedsbegivenheder**, filtrér på
   `rule.groups: syscheck AND syscheck.path: /etc/labapp/app.conf`.
   Åbn alarmen og find felterne `syscheck.event` (added/modified),
   `syscheck.changes`, md5/sha256 før/efter.

### Undersøgelsesspørgsmål
1. Hvilke tre konfigurationsproblemer har `legacy-web`? (Svar med
   kontrol-ID og titel.)
2. Hvilket problem ville du prioritere højest, og hvorfor?
3. Hvad viser FIM-alarmen om *hvad* der blev ændret – og hvad kan FIM *ikke*
   fortælle dig (fx hvem der ændrede, og hvorfor)?
4. Vis med kommandoer og dashboard-screendumps, at din remedering virkede.
5. Hvorfor genstartes agenten, før resultatet opdateres? (Intervallet er
   30 minutter – scan_on_start gør det straks.)

### Forventede observationer
- Før remedering: 3 fejlede kontroller (debug, anonym adgang, filtilladelser).
  NB: kan også ses som 3 røde kontroller på `legacy-web` med det samme, da
  baseline *allerede* er fejlkonfigureret.
- Efter remedering: 5/5 bestået.
- FIM-alarmtype: filændring på `/etc/labapp/app.conf` med checksum-diff.

### Aflevering
Fund (3 misconfigurations med controle-ID og bevis), FIM-alarm-analyse
(hændelsestype, tidsstempel, checksums), remedieringskommandoer og verifikation
(før/efter SCA-udfyldning).

---

## Lektion 3 – Threat hunting og IoCs (ca. 45 min)

### Læringsmål
- Udløse og analysere to angrebsscenarier (web-angreb, kompromitteret klient).
- Skille normale hændelser fra mislykkede angreb og mislykkede angreb fra
  en *gennemført* kompromittering.
- Bygge en kronologisk hændelsestidslinje med IP-adresser og tidsstempler.
- Vurdere root cause og anbefale handling (containment, afbødning).

### Kommandoer
```bash
./lab.sh scenario web-attack            # HTTP-log-simulering m. angreb
./lab.sh scenario compromised-client     # windowsstation-kompromittering
# eller manuelt i en enkelt container:
docker compose exec web-attack python3 /opt/lab/simulate.py web-attack --seed 42
docker compose exec client-01 python3 /opt/lab/simulate.py compromised-client --seed 42
```

Vigtige adresser (reserveret til dokumentation/undervisning, RFC 5737):

| Betydning                    | Adr.             | Type (range) |
|------------------------------|------------------|--------------|
| Intern normale klienter      | 10.0.100.x       | lab-intern   |
| Normal internettrafik        | 192.0.2.x        | TEST-NET-1   |
| Angribere (web + brute force)| 203.0.113.x      | TEST-NET-3   |
| Beacon/C2 + eksfiltrering    | 198.51.100.x      | TEST-NET-2   |

### Trin i Wazuh-dashboardet
1. **Sikkerhedsbegivenheder**: filtrér på `rule.groups:attack AND
   rule.groups:security_lab`. Sortér på tidsstempel.
2. Undersøg hvert alert-niveau ≥ 6 fra scenarierne:
   - 100110 (SQLi), 100111 (traversal), 100112 (foelsom fil), 100113
     (webshell/kommandoudførelse: kraftigste web-indikator!),
     100115 (fejl-burst).
   - 100120/100122 (mislykkede logins/brute force), 100123 (logget
     ind fra angriber-IP), 100130 (mistænkelig filoprettelse),
     100140 (forbindelse til IoC-IP), 100141 (eksfiltrerings-størrelse).
3. Sammenlign en 404-scanning (100114 base, 100115 aggregat) med en 200-svar
   til `shell.php?cmd=...` (100113): hvad gør den sidste til et
   kompromitteringsbevis?
4. Byg tidslinjen: brug felterne `timestamp`, `data.srcip/dstip`,
   `data.event_type`, `rule.id`.

### Undersøgelsesspørgsmål
1. Hvilke source-IP'er optræder i web-angrebet, og hvilken af dem udgør den
   mest sandsynlige kompromitteringskilde? Hvorfor?
2. Hvilken *enkelt* hændelse adskiller "forsøg på angreb" fra
   "gennemført kompromittering" i web-scenariet? (Hvilken rule-ID?)
3. I klient-scenariet: hvad er rækkefølgen brute force → succesfuld login →
   filoprettelse → beacon → eksfiltrering? Forklar med tidsstempler.
4. Hvilket endpoint ville du isolere først – og hvilken bevis-sikring
   (logs, FIM-billede) ville du tage, før du genstarter noget?
5. Ipr-adressen `198.51.100.99` modtog 8,5 MB fra `client-01`. Hvorfor er
   det et eksfiltrerings-*indikatium*, men ikke i sig selv bevis for
   datatyveri?

### Forventede observationer
- Flere alerts med niveau 3-12 fra reglerne ovenfor inden for ~1 minut efter
  aktivering.
- Normal trafik fra 10.0.100.x giver ingen alerts.
- Kompromitteringskriteriet: loginsucces + webshell-adgang (rule 100123/100113).

### Aflevering
En tidslinje med mindst fire relevante hændelser (tidsstempel, endpoint,
source/destination-IP, rule-ID, betydning) samt en kort vurdering:
"hvilken hændelse viser en muligt gennemført kompromittering, og hvorfor
tror vi det?"

---

## Lektion 4 – Detektionsengineering (ca. 45 min)

### Læringsmål
- Læse en Wazuh-detektionsregel (XML) og genkende felterne (if_sid, field,
  pcre2, level, frequency).
- Teste en regel med syntetiske hændelser i `wazuh-logtest`.
- Skrive/ændre en regel, reducere falske positiver og verificere.

### Kommandoer
```bash
# 1) se den eksisterende regel:
docker compose exec wazuh-manager cat /var/ossec/etc/rules/security_lab_rules.xml | less

# 2) starteniones interaktiv regel-test (indsæt én JSON-linje ad gangen):
docker compose exec -it wazuh-manager /var/ossec/bin/wazuh-logtest
```

Eksempel på test-hændelse (lim ind i wazuh-logtest):
```json
{"timestamp":"2025-06-11T09:00:00.000Z","sequence":1,"event_type":"http_request","endpoint":"web-attack","case_id":"SECURITY-LAB","synthetic":true,"srcip":"203.0.113.5","method":"GET","url":"/x?id=1 UNION SELECT 1,2,3--","status":200,"bytes":100,"result":"simulated"}
```
Forventet: fase 3 viser regel **100110** niveau 8.

### Trin – lav din egen regel
1. I filen `wazuh/rules/security_lab_rules.xml` (i repoet, mountes automatisk
   til manageren) tilføjes en ny regel med ID i intervallet **101000-101499**:
```xml
<!-- Elev-regel (eksempel): detekter soegning efter backup/zip-filer -->
<rule id="101001" level="6">
  <if_sid>100101</if_sid>
  <field name="url" type="pcre2">(?i)\.zip$|backup</field>
  <description>SECURITY-LAB: elevregel - backup/zip-soegning fra $(srcip).</description>
  <groups>web,recon,</groups>
</rule>
```
2. Genstart manageren: `docker compose restart wazuh-manager`
   (eller `docker compose exec wazuh-manager /var/ossec/bin/wazuh-control restart`).
3. Test med wazuh-logtest (se ovenfor). Verificér at en normal hændelse
   (`url:/index.html`) IKKE udløser reglen, mens `url:/backup.zip` gør.
4. Reducér falske positiver: overvej at kræve both `status=403/404` OG url-moensteret
   (to `<field>`-linjer), eller hæv `frequency`.

### Undersøgelsesspørgsmål
1. Hvad betyder `if_sid`, og hvorfor har din regel brug for det?
2. Hvordan matcher `<field name="url">` mod JSON-felterne fra logcollectoren?
3. For en `frequency`-regel (fx 100115): hvad sker der, hvis du sænker
   `frequency` til 3? Hvad er risikoen?
4. Hvorfor matcher din regel ikke hændelser fra andre case_id (fx ægte
   systemtelemetri)?

### Forventede observationer
- wazuh-logtest viser alle tre faser (prededecode/decode/filter).
- Din regel udløses på den tilsigtede hændelse og ikke på normal trafik.

### Aflevering
Én virkende regel (XML-uddrag) + kort testbeskrivelse (før test-hændelse,
efterlignende normal hændelse, wazuh-logtest-output for begge).

---

## Lektion 5 – Incident response (ca. 45 min)

### Læringsmål
- Prioritere tre sikkerhedsproblemer (misconfiguration, web-kompromittering,
  klient-kompromittering) begrundet i evidens.
- Dokumentere evidens systematisk (hvor kom den fra?–SCA, FIM eller logregel).
- Foreslå response-handlinger og remediere/gendanne miljøet.
- Reflektere over begrænsninger i evidensen (hvad ved vi ikke?).

### Situation
Du er security on duty. Laboratoriet har:
1. `legacy-web`: tre konfigurationsproblemer + en uautoriseret filændring
   (SCA + FIM-evidens).
2. `web-attack`: et muligt gennemført web-kompromittering (SQLi → webshell).
3. `client-01`: brute force, lykkelig login fra angriber-IP, persistence-fil,
   beacon + 8,5 MB "eksfiltrering".

### Kommandoer
```bash
# genudsæt scenarierne, hvis nogen har ryddet dem:
./lab.sh scenario misconfiguration
./lab.sh scenario web-attack
./lab.sh scenario compromised-client

# remediation af legacy-web:
docker compose exec legacy-web sh -c \
  "sed -i 's/^debug=.*/debug=false/; s/^anonymous_access=.*/anonymous_access=false/' /etc/labapp/app.conf && chmod 640 /etc/labapp/app.conf"
docker compose restart legacy-web

# "containment + oprydning" af client-01 (fjern persistence-filer, ryd logstatus):
docker compose exec client-01 python3 /opt/lab/simulate.py reset

# fuld reset af *scenarier* på alle endpoints (ikke-destruktiv; Wazuh-data bevares):
./lab.sh reset
```

### Trin
1. Find og prioriter problemstillingerne i dashboardet (Sikkerhedsbegivenheder
   + SCA + FIM). Skriv din prioritering (1-3) ned med begrundelse og
   evidenshenvisning (regel-ID/kontrol-ID).
2. Vælg handlinger pr. problem:
   - Er `legacy-web` aktivt udnyttet? Hvilken evidens ville du kræve?
3. Udfør remediationen ovenfor på `legacy-web`.
4. "Rens" `client-01` (fjern artifacts med `simulate.py reset`) og verificér:
   kommer der FIM-alarmer for slettede filer? Er SCA stadig grøn?
5. Diskuter begrænsninger: FIM viste *at* filen ændredes – ikke *hvem*;
   logregler viste *at* en stor forbindelse fandt sted – ikke dens *indhold*;
   SCA viser konfiguration *nu* – ikke historik. Hvad ville du gøre for at
   lukke disse huller i en produktion (auditd, netflow, EDR, baseline)?
6. Skriv incident-rapporten (aflevering nedenunder).

### Undersøgelsesspørgsmål (bruges i rapporten)
1. Hvilket problem har den højeste risiko/eksponering? Hvorfor?
2. Hvilke tre response-handlinger ville du udføre *først*, og i hvilken
   rækkefølge?
3. Hvordan verificerer du, at remediationen virkede, uden at ødelægge
   beviser?
4. Hvilke *typer* evidens mangler (netværk, filindhold, identitet)?

### Aflevering
Incident-rapport på 1-2 sider (skabelon):
- Sammendrag (hvad skete, hvornår, hvilke endpoints).
- Prioritering af de tre problemer med begrundelse.
- Tidslinje over de vigtigste hændelser (kan kopieres fra lektion 3/4).
- Udførte handlinger og verifikation (kommandoer + slutstatus).
- Begrænsninger og anbefalinger (hvad mangler vi, hvad bør måles fremover).

---

## Feedback og genanvendelighed
Efter hver lektion kan miljøet nulstilles med `./lab.sh reset` (scenariotilstand)
eller helt rebuildes med `./lab.sh down && ./lab.sh up`.
