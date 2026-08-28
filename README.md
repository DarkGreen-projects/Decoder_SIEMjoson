# Decoder SIEM

Tool **Python** CLI + GUI (Gradio) per analizzare incidenti SIEM: estrae IOC e metadati da log multi-vendor e arricchisce con OSINT opzionale (VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus).

Parte del portfolio [DarkGreen Projects](https://github.com/DarkGreen-projects). Complementare alla demo browser [SOC Automation Hub](https://darkgreen-projects.github.io/soc-automation-hub/) (hunt pack e coverage MITRE senza API obbligatorie).

## Cosa fa

| Capacità | Dettaglio |
|----------|-----------|
| **Parse multi-vendor** | JSON Cynet/Defender, CEF/syslog FortiGate, email (.eml), IOC raw |
| **Estrazione IOC** | IP, hash, domain, URL, path, hostname, utente |
| **OSINT opzionale** | VT, AbuseIPDB, OTX, URLhaus — cache SQLite 24h su hash/URL/domain |
| **Output** | JSON strutturato + report Markdown per analisti |
| **GUI locale** | Gradio su `http://127.0.0.1:7860` |
| **CLI / batch** | Singolo file o cartella ricorsiva |

## Modalità

| Modalità | Comando | Quando usarla |
|----------|---------|---------------|
| **GUI** | `python -m decoder_siem.gui` | Triage interattivo, incolla alert |
| **CLI analyze** | `decoder-siem analyze ./incident.json -o ./out/report.json --markdown ./out/report.md` | Pipeline, automazione |
| **CLI extract-only** | `decoder-siem extract-only ./alert.json -o ./out/report.json` | Solo estrazione, senza API |

## Avvio rapido

```powershell
git clone https://github.com/DarkGreen-projects/Decoder_SIEMjoson.git
cd Decoder_SIEMjoson
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[gui]"
copy .env.example .env
# opzionale: aggiungi VT_API_KEY, ABUSEIPDB_API_KEY, …
python -m decoder_siem.gui
```

**Senza chiavi API** l'estrazione funziona; gli IOC compaiono come non verificati.

Prova CLI con fixture:

```powershell
python -m decoder_siem extract-only ./tests/fixtures/cynet_malicious_pdf.json -o ./out/report.json
```

## Struttura repository

```
Decoder_SIEMjoson/
├── decoder_siem/     # Parser, enricher, GUI, CLI
├── docs/wiki/        # Guide complete (install Windows, API, formati)
├── tests/            # pytest + fixture anonimizzate
└── pyproject.toml
```

## Documentazione

| Guida | Contenuto |
|-------|-----------|
| [docs/wiki/Home.md](docs/wiki/Home.md) | Indice wiki |
| [Installazione Windows da zero](docs/wiki/Installazione-Windows-da-zero.md) | PC senza Python/Git |
| [Configurazione chiavi API](docs/wiki/Configurazione-chiavi-API.md) | OSINT |
| [Formati supportati](docs/wiki/Formati-supportati.md) | Input vendor |

## Sviluppo locale

```powershell
pip install -e ".[gui,dev]"
pytest -q
```

Requisiti: **Python 3.11+**

## Dati e sicurezza

- Non committare JSON incidenti reali, `.env` o cache con dati sensibili.
- Usa solo fixture di test o dati anonimizzati nei report pubblici.
- Le chiavi API restano solo in locale (`.env`, già in `.gitignore`).

## Portfolio correlato

- [SOC Automation Hub](https://github.com/DarkGreen-projects/soc-automation-hub) — demo web: SIEM Decoder (browser), Alert Rule Planner, CSV VT, Pivot, Bulk IOC
- [darkgreenos](https://github.com/DarkGreen-projects/darkgreenos) — OS sperimentale / systems

## Licenza

MIT — vedi repository per dettagli.
