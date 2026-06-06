# Formati supportati

## Tabella riepilogativa

| Formato | Input | Vendor |
|---------|-------|--------|
| Cynet / SIEM JSON | `.json` | `Cynet` |
| Microsoft Defender | `.json` (`MicrosoftGraph`) | `MicrosoftDefender` |
| FortiGate CEF | `.cef`, `.log`, `.txt` | `FortiGate` |
| CEF in JSON wrapper | `.json` (campo `message`, `raw`) | `FortiGate` |
| Email adattiva | GUI, `.eml`, `.txt` | `EmailHeaders` |
| IOC diretti | GUI, `.txt` | `RawIOC` |

---

## JSON Cynet

File JSON con chiave `Cynet` o struttura incidente Cynet.

Estrae: IP, SHA-256, path, hostname, utente, malware ID, domini, URL.

---

## Microsoft Defender

JSON con chiave `MicrosoftGraph` o alert Graph API.

Estrae: evidence IP/device, URL alert, MITRE ATT&CK, gruppi AD, incident ID.

---

## FortiGate CEF

Riga syslog con prefisso `CEF:0|Fortinet|...`.

Estrae: syslog, CEF header, extension (IP, URL, device ID, severity).

Eventi **system** (es. shutdown) spesso senza IOC ma con contesto operativo.

---

## Email adattiva

Vedi [Analisi email adattiva](Analisi-email-adattiva.md).

Profili: `headers_only`, `headers_body`, `full_mime`.

---

## IOC diretti

Uno o più indicatori separati da spazio, virgola o `;`:

- IP v4/v6
- SHA256 (64 hex), SHA1 (40), MD5 (32)
- URL (`http://` / `https://`)
- Domini

Ogni token deve essere un IOC valido (testo libero misto viene rifiutato).

---

## Ordine di rilevamento

1. JSON
2. CEF/syslog
3. Header email
4. Lista IOC diretti
5. Errore «formato non riconosciuto»
