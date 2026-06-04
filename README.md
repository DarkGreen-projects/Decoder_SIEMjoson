# Decoder SIEM JSON

Strumento CLI in Python per analizzare incidenti SIEM in formato **JSON** (es. **Cynet**) e log **CEF/syslog** (es. **FortiGate**): estrae IOC e metadati, con arricchimento opzionale tramite **VirusTotal API v3**.

## Requisiti

- Python 3.11+
- Chiave API VirusTotal (solo per arricchimento; l'estrazione funziona senza)

## Installazione

```bash
cd /workspace
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Configura le variabili d'ambiente:

```bash
cp .env.example .env
# Modifica .env e imposta VT_API_KEY
```

## Utilizzo

### Solo estrazione (senza API)

```bash
# Cynet JSON
python -m decoder_siem extract-only ./tests/fixtures/cynet_malicious_pdf.json -o ./out/report.json

# FortiGate CEF (syslog)
python -m decoder_siem extract-only ./tests/fixtures/fortigate_shutdown.cef -o ./out/fortigate_report.json -m ./out/fortigate_report.md
```

### Estrazione + VirusTotal

```bash
export VT_API_KEY="your_key"
decoder-siem analyze ./incident.json -o ./out/report.json --markdown ./out/report.md
```

### Batch su cartella

```bash
decoder-siem analyze ./alerts/ --recursive
```

### Opzioni utili

| Opzione | Descrizione |
|---------|-------------|
| `--no-enrich` | Salta VirusTotal |
| `--rpm 4` | Richieste/minuto (rispetta quota free tier) |
| `--cache-dir ./.cache` | Cache locale risposte VT |

## Formati supportati

| Formato | Estensioni | Vendor rilevato |
|---------|------------|-----------------|
| Cynet / SIEM JSON | `.json` | `Cynet` |
| FortiGate syslog+CEF | `.cef`, `.log`, `.txt` | `FortiGate` |
| CEF in wrapper JSON | `.json` (campo `message`, `raw`, `log`) | `FortiGate` |

Gli eventi FortiGate di tipo **system** (es. shutdown) spesso non contengono IOC: il report include comunque hostname, device ID, severità e messaggio. I log **traffic/utm** espongono IP (`FTNTFGTsrcip`, `FTNTFGTdstip`), URL e domini.

## Cosa estrae

Dal JSON Cynet (e in generale da qualsiasi JSON annidato):

- **IP** (`HostIp`, testo `Host IP:`, JSON interno) — IP privati marcati come `internal`
- **SHA-256** (file infetto, processi parent/grandparent)
- **Path** file e processi
- **Hostname**, **utente**, **Malware ID/type**
- **Domini** e **URL** se presenti (`AlertDomain`, `AlertUrl`, regex)

Gli IP RFC1918 (es. `192.168.x.x`) **non** vengono inviati a VirusTotal; compaiono nel report nella sezione *Rete interna*.

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

## Estensioni future

Architettura a plugin per enricher aggiuntivi (AbuseIPDB, OTX, ecc.) e altri vendor SIEM oltre Cynet e FortiGate.
