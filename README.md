# Decoder SIEM JSON

Strumento CLI in Python per analizzare incidenti SIEM in formato JSON (es. **Cynet**): estrae IOC (IP, hash, domini, URL, path, utenti) e li arricchisce opzionalmente tramite **VirusTotal API v3**.

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
decoder-siem extract-only ./tests/fixtures/cynet_malicious_pdf.json -o ./out/report.json
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

## Cosa estrae

Dal JSON Cynet (e in generale da qualsiasi JSON annidato):

- **IP** (`HostIp`, testo `Host IP:`, JSON interno) — IP privati marcati come `internal`
- **SHA-256** (file infetto, processi parent/grandparent)
- **Path** file e processi
- **Hostname**, **utente**, **Malware ID/type**
- **Domini** e **URL** se presenti (`AlertDomain`, `AlertUrl`, regex)

Gli IP RFC1918 (es. `192.168.x.x`) **non** vengono inviati a VirusTotal; compaiono nel report nella sezione *Rete interna*.

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

Architettura a plugin per enricher aggiuntivi (AbuseIPDB, OTX, ecc.) e altri vendor SIEM oltre Cynet.
