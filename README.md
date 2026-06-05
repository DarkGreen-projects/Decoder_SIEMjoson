# Decoder SIEM JSON

Strumento CLI in Python per analizzare incidenti SIEM in formato **JSON** (es. **Cynet**) e log **CEF/syslog** (es. **FortiGate**): estrae IOC e metadati, con arricchimento opzionale tramite **VirusTotal**, **AbuseIPDB**, **AlienVault OTX** e **URLhaus** (abuse.ch).

## Requisiti

- Python 3.11+
- Chiavi API opzionali per l'arricchimento (l'estrazione funziona senza)

## Installazione

```bash
cd /workspace
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Con interfaccia grafica (Gradio)
pip install -e ".[gui]"
```

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
2. Incolla nel campo testo un JSON (Cynet, Microsoft Defender) o un log CEF FortiGate
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
| `--cache-dir ./.cache` | Cache locale risposte enricher |

## Formati supportati

| Formato | Estensioni | Vendor rilevato |
|---------|------------|-----------------|
| Cynet / SIEM JSON | `.json` | `Cynet` |
| Microsoft Defender / Graph | `.json` (chiave `MicrosoftGraph`) | `MicrosoftDefender` |
| FortiGate syslog+CEF | `.cef`, `.log`, `.txt` | `FortiGate` |
| CEF in wrapper JSON | `.json` (campo `message`, `raw`, `log`) | `FortiGate` |
| Header email / messaggio RFC 5322 | incollati in GUI, `.eml`, `.txt` | `EmailHeaders` |

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

## Analisi header email

Incolla gli header da «Mostra originale» (Outlook/Gmail) o un file `.eml`. Il tool:

- Calcola **criticità** (0–100) e classifica: **phishing**, **spam** o **altro**
- Analizza SPF/DKIM/DMARC, allineamento From/Reply-To/Return-Path, catena `Received`
- Estrae IP e domini dagli header per arricchimento OSINT

La classificazione è **euristica locale** (non ML). Il corpo MIME e gli allegati non sono analizzati in profondità in questa versione.
