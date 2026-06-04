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

# Con interfaccia grafica (Gradio)
pip install -e ".[gui]"
```

Configura le variabili d'ambiente:

```bash
cp .env.example .env
# Modifica .env e imposta VT_API_KEY
```

## Utilizzo

### Interfaccia grafica (GUI)

Avvia la GUI locale su `http://127.0.0.1:7860`:

```bash
pip install -e ".[gui]"
python -m decoder_siem.gui
# oppure: decoder-siem-gui
```

Flusso:

1. Configura `VT_API_KEY` nel file `.env` (obbligatorio per l'arricchimento VT in GUI)
2. Incolla nel campo testo un JSON (Cynet, Microsoft Defender) o un log CEF FortiGate
3. Premi **Analizza** (pulsante accanto al campo) — VirusTotal è **sempre attivo** se la chiave è presente
4. A sinistra: **Riepilogo incidente**; a destra: **Elementi analizzati** con colori:
   - Verde (`#2e7d32`): elementi non potenzialmente malevoli
   - Rosso carmino (`#960018`): elementi malevoli secondo VirusTotal
5. Sotto: tabella dettagliata (provenienza, stato VT)
6. Premi **Pulisci** per svuotare tutto e inserire un nuovo alert

Senza `VT_API_KEY` l'estrazione funziona comunque; gli IOC compaiono in verde come «non verificato».

### Solo estrazione (senza API)

```bash
# Cynet JSON
python -m decoder_siem extract-only ./tests/fixtures/cynet_malicious_pdf.json -o ./out/report.json

# FortiGate CEF (syslog)
python -m decoder_siem extract-only ./tests/fixtures/fortigate_shutdown.cef -o ./out/fortigate_report.json -m ./out/fortigate_report.md

# Microsoft Defender (Graph API alert)
python -m decoder_siem extract-only ./tests/fixtures/defender_ldap_recon.json -o ./out/defender_report.json
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
| Microsoft Defender / Graph | `.json` (chiave `MicrosoftGraph`) | `MicrosoftDefender` |
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

## Estensioni future

Architettura a plugin per enricher aggiuntivi (AbuseIPDB, OTX, ecc.) e altri vendor SIEM oltre Cynet e FortiGate.
