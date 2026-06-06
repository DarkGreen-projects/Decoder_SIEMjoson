# Architettura

## Flusso generale

```
Input (testo/file)
    ↓
load_text / load_document     ← rilevamento formato
    ↓
_extract_from_document        ← estrazione IOC + contesto
    ↓
_apply_enrichment             ← OSINT + cache SQLite
    ↓
Report (JSON, Markdown, GUI)
```

---

## Moduli principali

| Modulo | Ruolo |
|--------|-------|
| `parsers/loader.py` | Rilevamento formato (JSON, CEF, email, IOC) |
| `parsers/email.py` | Parsing RFC 5322, MIME, allegati |
| `parsers/ioc_list.py` | Tokenizzazione IOC diretti |
| `extractors/` | Estrazione per vendor (Cynet, Defender, FortiGate, email) |
| `analyzers/email_scorer.py` | Verdetto email (header + corpo + allegati) |
| `analyzers/email_content.py` | Segnali corpo HTML e allegati |
| `pipeline.py` | Orchestrazione completa |
| `enrichers/` | Client VT, AbuseIPDB, OTX, URLhaus |
| `enrichment_cache.py` | Cache SQLite TTL |
| `correlation.py` | Correlazione IOC XDR |
| `known_benign.py` | Infrastrutture note |
| `alert_guidance.py` | Guida SOC contestuale |
| `gui.py` | Interfaccia Gradio |
| `cli.py` | Interfaccia Typer |

---

## Formati documento

```python
DocumentFormat = "json" | "cef" | "email" | "ioc"
```

---

## Sicurezza input

`input_guard.py` applica:

- Limite caratteri input (default 2M)
- Limite file (default 20 MB)
- Profondità JSON max
- Max IOC estratti (default 500)
- Sanitizzazione output Markdown

---

## Test

```bash
pytest -q
```

125+ test automatizzati in `tests/`.
