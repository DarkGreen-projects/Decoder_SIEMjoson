# Decoder SIEM

**[Wiki completa del progetto](docs/wiki/Home.md)** — installazione da zero su Windows, guide GUI/CLI, formati, OSINT e troubleshooting.

Strumento CLI e GUI in Python per analizzare incidenti SIEM e indicatori di compromissione (IOC):

- **JSON** (Cynet, Microsoft Defender)
- **CEF/syslog** (FortiGate)
- **Email adattiva** — header, corpo plain/HTML, link e allegati (`.eml` o incolla)
- **IOC diretti** — singolo IP, hash, URL o dominio, oppure più valori separati da spazio, virgola o `;`

Estrae IOC e metadati, con arricchimento opzionale tramite **VirusTotal**, **AbuseIPDB**, **AlienVault OTX** e **URLhaus** (abuse.ch). Le risposte OSINT per hash, URL e domini sono memorizzate in **cache SQLite** (TTL 24 ore); gli IP vengono sempre interrogati live.

## Requisiti

- Python 3.11+
- Chiavi API opzionali per l'arricchimento (l'estrazione funziona senza)

> **Windows senza Python?** Segui la guida passo-passo: [Installazione Windows da zero](docs/wiki/Installazione-Windows-da-zero.md)

## Installazione

### Linux / macOS

```bash
git clone https://github.com/DarkGreen-projects/Decoder_SIEMjson.git
cd Decoder_SIEMjson
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[gui]"
```

### Windows (PowerShell)

```powershell
git clone https://github.com/DarkGreen-projects/Decoder_SIEMjson.git
cd Decoder_SIEMjson
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[gui]"
```

Vedi [wiki installazione Windows](docs/wiki/Installazione-Windows-da-zero.md) per PC senza Git/Python.

Configura le variabili d'ambiente:

```bash
cp .env.example .env
# Modifica .env con le chiavi che vuoi usare (almeno una per l'arricchimento OSINT)
```

### Chiavi API (gratuite o free tier)

| Servizio | Variabile `.env` | Registrazione |
|----------|------------------|---------------|
| VirusTotal | `VT_API_KEY` | https://www.virustotal.com/gui/my-apikey |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | https://www.abuseipdb.com/account/api (~1000 check/giorno) |
| AlienVault OTX | `OTX_API_KEY` | https://otx.alienvault.com → Settings → API Integration |
| URLhaus | `URLHAUS_AUTH_KEY` | https://auth.abuse.ch/ (Auth-Key gratuita, obbligatoria per le query API) |

Rate limit consigliati: `VT_REQUESTS_PER_MINUTE=4`, `OSINT_REQUESTS_PER_MINUTE=30`.

## Utilizzo

### Interfaccia grafica (GUI)

Avvia la GUI locale su `http://127.0.0.1:7860`:

```bash
pip install -e ".[gui]"
python -m decoder_siem.gui
# oppure: decoder-siem-gui
```

Flusso:

1. Configura nel file `.env` le chiavi OSINT che vuoi usare
2. Incolla nel campo testo uno dei formati supportati:
   - JSON (Cynet, Microsoft Defender)
   - log CEF/syslog (FortiGate)
   - email: header («Mostra originale»), file `.eml` completo o MIME con corpo/allegati
   - **IOC diretti** (es. `8.8.8.8`, un hash SHA256, oppure `8.8.8.8, abc...64 def...64`)
3. Premi **Analizza** — vengono chiamate tutte le fonti per cui è presente la chiave
4. A sinistra: **Riepilogo incidente**; a destra: **Elementi analizzati** con colori:
   - Verde (`#2e7d32`): elementi non potenzialmente malevoli
   - Rosso carmino (`#960018`): elementi malevoli secondo **OSINT aggregato** (VT, AbuseIPDB, OTX, URLhaus)
5. Sotto: tabella con colonne VT, AbuseIPDB, OTX, URLhaus e link OSINT
6. Premi **Pulisci** per svuotare tutto e inserire un nuovo alert

Il footer predefinito Gradio («Use via API», «Built with Gradio») è disabilitato; in basso resta solo il copyright del progetto.

Senza chiavi API l'estrazione funziona comunque; gli IOC pubblici compaiono come «non verificato».

### Solo estrazione (senza API)

```bash
# Cynet JSON
python -m decoder_siem extract-only ./tests/fixtures/cynet_malicious_pdf.json -o ./out/report.json

# FortiGate CEF (syslog)
python -m decoder_siem extract-only ./tests/fixtures/fortigate_shutdown.cef -o ./out/fortigate_report.json -m ./out/fortigate_report.md

# Microsoft Defender (Graph API alert)
python -m decoder_siem extract-only ./tests/fixtures/defender_ldap_recon.json -o ./out/defender_report.json
```

### Estrazione + arricchimento OSINT

```bash
export VT_API_KEY="your_key"
export ABUSEIPDB_API_KEY="your_key"
export OTX_API_KEY="your_key"
export URLHAUS_AUTH_KEY="your_key"
decoder-siem analyze ./incident.json -o ./out/report.json --markdown ./out/report.md
```

### Batch su cartella

```bash
decoder-siem analyze ./alerts/ --recursive
```

### Opzioni utili

| Opzione | Descrizione |
|---------|-------------|
| `--no-enrich` | Salta tutte le API OSINT |
| `--rpm 4` | Richieste/minuto VirusTotal (quota free tier) |
| `--cache-path ./cache.db` | Percorso database SQLite cache OSINT |
| `--no-cache` | Disabilita cache (hash/URL/domini sempre live) |
| `--cache-ttl-hours 24` | TTL cache in ore (default 24) |

## Formati supportati

| Formato | Estensioni | Vendor rilevato |
|---------|------------|-----------------|
| Cynet / SIEM JSON | `.json` | `Cynet` |
| Microsoft Defender / Graph | `.json` (chiave `MicrosoftGraph`) | `MicrosoftDefender` |
| FortiGate syslog+CEF | `.cef`, `.log`, `.txt` | `FortiGate` |
| CEF in wrapper JSON | `.json` (campo `message`, `raw`, `log`) | `FortiGate` |
| Email adattiva (header, corpo, allegati MIME) | incollati in GUI, `.eml`, `.txt` | `EmailHeaders` |
| IOC diretti (IP, hash, URL, dominio) | incollati in GUI, `.txt` | `RawIOC` |

### IOC diretti

Puoi analizzare uno o più indicatori senza un alert completo. Incolla nel campo testo (GUI) o in un file `.txt`:

```text
8.8.8.8
```

```text
aabbccdd...64caratterihex
```

```text
8.8.8.8, dddd...40caratterihex, aabbcc...64caratterihex
```

```text
hash1 hash2 hash3
```

Separatori ammessi: **spazio**, **virgola**, **punto e virgola**, **a capo**. Ogni IOC viene arricchito con le stesse fonti OSINT degli alert completi; hash, URL e domini usano la cache SQLite (24 h), gli IP no.

```bash
# File con IOC su una riga
decoder-siem analyze ./iocs.txt -o ./out/iocs_report.json --markdown ./out/iocs_report.md
```

Gli eventi FortiGate di tipo **system** (es. shutdown) spesso non contengono IOC: il report include comunque hostname, device ID, severità e messaggio. I log **traffic/utm** espongono IP (`FTNTFGTsrcip`, `FTNTFGTdstip`), URL e domini.

## Cosa estrae

Dal JSON Cynet (e in generale da qualsiasi JSON annidato):

- **IP** (`HostIp`, testo `Host IP:`, JSON interno) — IP privati marcati come `internal`
- **SHA-256** (file infetto, processi parent/grandparent)
- **Path** file e processi
- **Hostname**, **utente**, **Malware ID/type**
- **Domini** e **URL** se presenti (`AlertDomain`, `AlertUrl`, regex)

Gli IP RFC1918 (es. `192.168.x.x`) **non** vengono inviati a VirusTotal; compaiono nel report nella sezione *Rete interna*.

Dal JSON Microsoft Defender (`MicrosoftGraph`):

- **Evidence**: IP (`ipEvidence`, `lastIpAddress`, `lastExternalIpAddress`), device (`deviceDnsName`, `hostName`), URL alert
- **Contesto**: titolo, detector, MITRE ATT&CK, severità, incident ID
- **Gruppi AD** target (`securityGroupEvidence.friendlyName`)
- IP interni (`172.27.x.x`, `10.x.x.x`, `::1`) esclusi da VirusTotal; IP esterni arricchibili

Dal CEF FortiGate:

- **Syslog**: priority, timestamp, hostname firewall
- **CEF header**: vendor, product, signature, event name, severity
- **Extension**: `deviceExternalId`, `FTNTFGTlogdesc`, `msg`, IP/URL (se presenti)

Dalle email (analisi adattiva al contenuto fornito):

- **Header**: mittente, Reply-To, Return-Path, SPF/DKIM/DMARC, catena `Received`
- **Corpo** (se presente): testo plain/HTML, URL, linguaggio phishing, link mismatch
- **Allegati** (se presenti in `.eml`): nome file, tipo MIME, hash SHA256 per VT/OSINT
- **Verdetto**: phishing, spam, safe o non classificabile con criticità 0–100

```bash
# Analisi file .eml completo (corpo HTML + allegati)
decoder-siem analyze ./sospetto.eml -o ./out/email_report.json --markdown ./out/email_report.md
```

## Output

- **JSON**: struttura completa con provenienza di ogni artefatto e risultati enricher
- **Markdown**: report leggibile per analisti SOC

## Test

```bash
pytest -q
```

## Privacy

I JSON incidenti possono contenere path, nomi host e utenti reali. Non committare file sensibili; usa `.env` solo in locale (già in `.gitignore`).

## Arricchimento OSINT

Per ogni IOC pubblico (IP, hash, dominio, URL) la pipeline interroga, se configurato:

1. **URLhaus** — URL/host/hash malevoli (feed abuse.ch)
2. **AbuseIPDB** — reputation IP (score e segnalazioni)
3. **OTX** — pulse e contesto threat intel
4. **VirusTotal** — detection ratio e permalink

Il verdetto in GUI e tabella è **aggregato**: basta una fonte che segnali minaccia per colorare l'IOC in rosso carmino.

### Cache SQLite (TTL 24 ore)

Hash, URL e domini già analizzati vengono riutilizzati dalla cache locale per ridurre chiamate API e tempi di risposta. Gli **IP non sono cachati** e restano sempre live. La cache è attiva di default; percorso configurabile con `ENRICHMENT_CACHE_PATH` o `--cache-dir`.

### Correlazione contestuale

Negli alert XDR (es. Microsoft Defender), path e URL correlati a un hash già presente nell'evento possono essere esclusi dall'arricchimento VT ridondante, velocizzando l'analisi senza perdere contesto.

### Infrastrutture note

Domini e host di provider legittimi noti (Google, Microsoft, CDN, ecc.) sono etichettati come benigni: link VT disponibili senza chiamate API automatiche superflue.

## Analisi email adattiva

L'analisi email **non si limita agli header**: il programma rileva automaticamente quanto contenuto è disponibile nell'input e approfondisce di conseguenza.

Incolla gli header da «Mostra originale» (Outlook/Gmail), un file `.eml` completo o MIME multipart incollato. L'analisi si adatta al contenuto disponibile (`content_profile`):

| Input fornito | Analisi eseguita |
|---------------|------------------|
| Solo header | SPF/DKIM/DMARC, identità, Received, subject |
| Header + corpo | Header + testo plain/HTML, link, linguaggio phishing |
| `.eml` con allegati | Header + corpo + hash SHA256 allegati (VT/OSINT) |

Profili rilevati automaticamente: `headers_only`, `headers_body`, `full_mime`.

Il tool:

- Calcola **criticità** (0–100) e classifica: **phishing**, **spam**, **safe** o **non classificabile**
- Rileva **link mismatch** HTML (testo visibile ≠ href), URL shortener e TLD sospetti
- Segnala allegati pericolosi (`.exe`, `.docm`, doppia estensione, archivi)
- Estrae IOC da header, corpo e hash allegati per arricchimento OSINT

La classificazione è **euristica locale** (non ML): non sostituisce sandbox o analisi forense completa, ma copre header, corpo e allegati presenti nell'input.

## Sicurezza input

Validazione dimensionale e sanitizzazione su input incollati e file caricati: limiti su caratteri, profondità JSON, numero massimo di IOC estratti e valori artefatto. Protegge da payload eccessivi, JSON annidati e contenuti non sicuri in output Markdown.

## Documentazione (Wiki)

| Guida | Descrizione |
|-------|-------------|
| [Home Wiki](docs/wiki/Home.md) | Indice completo |
| [Windows da zero](docs/wiki/Installazione-Windows-da-zero.md) | Installazione da PC vuoto |
| [Guida GUI](docs/wiki/Guida-GUI.md) | Interfaccia grafica |
| [Guida CLI](docs/wiki/Guida-CLI.md) | Riga di comando |
| [Chiavi API](docs/wiki/Configurazione-chiavi-API.md) | Setup OSINT |
| [Formati](docs/wiki/Formati-supportati.md) | Input supportati |
| [Email adattiva](docs/wiki/Analisi-email-adattiva.md) | Header, corpo, allegati |
| [Troubleshooting](docs/wiki/Risoluzione-problemi.md) | Errori comuni |
