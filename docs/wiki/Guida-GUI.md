# Guida GUI

L'interfaccia grafica è basata su **Gradio** e si avvia in locale.

## Avvio

```bash
decoder-siem-gui
```

URL predefinito: **http://127.0.0.1:7860**

---

## Layout

| Area | Contenuto |
|------|-----------|
| Campo testo (sinistra) | Incolla JSON, CEF, email, IOC diretti |
| Pulsante **Analizza** | Avvia pipeline completa |
| **Riepilogo incidente** | Vendor, host, verdetto email, auth |
| **Elementi analizzati** | IOC colorati (verde = ok, rosso carmino = malevolo OSINT) |
| **Tabella dettaglio** | Colonne VT, AbuseIPDB, OTX, URLhaus |
| **Guida all'alert** | Spiegazione contestuale e azioni suggerite |
| **Pulisci** | Reset completo dell'interfaccia |

---

## Cosa incollare

### JSON Cynet / Defender

Incolla il blocco JSON completo che inizia con `{`.

### Log CEF FortiGate

Incolla la riga syslog con `CEF:0|...`.

### Email

- Header da «Mostra originale» (Outlook/Gmail)
- File `.eml` completo (corpo HTML + allegati)
- MIME multipart incollato

### IOC diretti

```
8.8.8.8
```

```
aabbcc...64caratterihex
```

```
8.8.8.8, hash1 hash2
```

---

## Colori IOC

| Colore | Significato |
|--------|-------------|
| Verde `#2e7d32` | Nessuna minaccia rilevata da OSINT |
| Rosso carmino `#960018` | Almeno una fonte OSINT segnala minaccia |
| Grigio | IP interni / non arricchiti VT |

---

## Senza chiavi API

L'estrazione funziona comunque. Il riquadro **Messaggi** avvisa quali enricher sono disattivati. Gli IOC compaiono come «non verificato».

---

## Footer

Il footer predefinito Gradio («Built with Gradio») è disabilitato. Resta solo il copyright del progetto.
