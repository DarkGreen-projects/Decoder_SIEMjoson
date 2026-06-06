# Decoder SIEM — Wiki

Benvenuto nella documentazione completa del progetto **Decoder SIEM**.

Decoder SIEM è uno strumento Python per analisti SOC che estrae indicatori di compromissione (IOC) da alert SIEM, email e input diretti, con arricchimento opzionale tramite fonti OSINT.

## Indice

| Pagina | Contenuto |
|--------|-----------|
| [Installazione Windows da zero](Installazione-Windows-da-zero.md) | Guida passo-passo da PC Windows vuoto (senza Python) |
| [Installazione Linux e macOS](Installazione-Linux-macOS.md) | Setup su sistemi Unix |
| [Configurazione chiavi API](Configurazione-chiavi-API.md) | VirusTotal, AbuseIPDB, OTX, URLhaus |
| [Guida GUI](Guida-GUI.md) | Interfaccia grafica Gradio |
| [Guida CLI](Guida-CLI.md) | Comandi da terminale |
| [Formati supportati](Formati-supportati.md) | JSON, CEF, email, IOC diretti |
| [Analisi email adattiva](Analisi-email-adattiva.md) | Header, corpo HTML, allegati |
| [OSINT e cache](OSINT-e-cache.md) | Enrichment, SQLite TTL, correlazione |
| [Architettura](Architettura.md) | Flusso interno del programma |
| [Risoluzione problemi](Risoluzione-problemi.md) | Errori comuni e fix |

## Avvio rapido (se hai già Python)

```powershell
git clone https://github.com/DarkGreen-projects/Decoder_SIEMjoson.git
cd Decoder_SIEMjoson
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[gui]"
copy .env.example .env
decoder-siem-gui
```

Apri il browser su **http://127.0.0.1:7860**.

## Cosa può analizzare

- **JSON** — Cynet, Microsoft Defender (Graph API)
- **CEF/syslog** — FortiGate e altri vendor
- **Email adattiva** — header, corpo plain/HTML, allegati `.eml`
- **IOC diretti** — IP, hash, URL, domini (singoli o multipli)

## Repository

https://github.com/DarkGreen-projects/Decoder_SIEMjoson
