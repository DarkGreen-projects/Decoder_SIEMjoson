# Guida CLI

Il comando principale è `decoder-siem`.

## Comandi

### version

```bash
decoder-siem version
```

### extract-only

Estrae IOC **senza** chiamate API:

```bash
decoder-siem extract-only incident.json -o out/report.json
decoder-siem extract-only alert.cef -o out/report.json -m out/report.md
```

### analyze

Estrazione + arricchimento OSINT (legge `.env`):

```bash
decoder-siem analyze incident.json -o out/report.json --markdown out/report.md
```

---

## Opzioni analyze

| Opzione | Descrizione |
|---------|-------------|
| `--no-enrich` | Salta tutte le API OSINT |
| `--rpm 4` | Richieste/minuto VirusTotal |
| `--no-cache` | Disabilita cache SQLite |
| `--cache-path ./cache.db` | Percorso database cache |
| `--cache-ttl-hours 24` | TTL cache in ore |
| `--recursive` / `-r` | Analizza cartella ricorsivamente |
| `--max-input-mb N` | Limite dimensione input |

---

## Estensioni supportate

`.json`, `.log`, `.txt`, `.cef`, `.eml`

---

## Batch su cartella

```bash
decoder-siem analyze ./alerts/ --recursive
```

Ogni file produce un report in `./out/<nome>_report.json`.

---

## Esempi

```bash
# FortiGate CEF
decoder-siem analyze ./fortigate.cef -o ./out/fg.json -m ./out/fg.md

# Email .eml completa
decoder-siem analyze ./phishing.eml -o ./out/email.json

# IOC in file .txt
decoder-siem analyze ./iocs.txt -o ./out/iocs.json
```
