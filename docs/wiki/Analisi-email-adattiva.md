# Analisi email adattiva

L'analisi email si adatta automaticamente al contenuto disponibile nell'input.

## Profili (`content_profile`)

| Profilo | Quando | Cosa viene analizzato |
|---------|--------|----------------------|
| `headers_only` | Solo header incollati | SPF/DKIM/DMARC, identità, Received |
| `headers_body` | Header + corpo testo | Header + plain text |
| `full_mime` | `.eml` multipart | Header + HTML + link + allegati |

---

## Verdetto

| Esito | Significato |
|-------|-------------|
| `phishing` | Indicatori forti di phishing (auth fail, link mismatch, allegati pericolosi) |
| `spam` | Pattern bulk/marketing |
| `safe` | Nessun indicatore rilevante |
| `unclassifiable` | Header insufficienti o malformati |

Criticità: **0–100**. Confidenza: nullo / bassa / media / alta.

---

## Segnali corpo (se presente)

- Linguaggio phishing (password, verify account, urgent action)
- **Link mismatch HTML**: testo link ≠ URL reale (`https://bank.com` → `https://evil.com`)
- URL shortener (bit.ly, t.co, …)
- TLD sospetti
- Corpo vuoto con soli link

---

## Segnali allegati (se presenti in `.eml`)

- Estensioni ad alto rischio: `.exe`, `.scr`, `.js`, `.vbs`, `.lnk`, `.hta`, …
- Doppia estensione: `invoice.pdf.exe`
- Office con macro: `.docm`, `.xlsm`, `.pptm`
- Archivi: `.zip`, `.rar`, `.7z`
- Hash **SHA256** di ogni allegato → arricchimento VirusTotal

---

## Come ottenere il massimo dall'analisi

1. **Solo header**: incolla «Mostra originale» da Outlook/Gmail
2. **Header + corpo**: incolla header e testo dopo una riga vuota
3. **Analisi completa**: salva il messaggio come `.eml` e analizzalo via GUI o CLI

```bash
decoder-siem analyze ./messaggio.eml -o ./out/email.json
```

---

## Limiti di sicurezza

- Max allegati analizzati: 20 (configurabile con `DECODER_MAX_EMAIL_ATTACHMENTS`)
- Max dimensione singolo allegato: 5 MB (`DECODER_MAX_EMAIL_ATTACHMENT_BYTES`)
- Corpo troncato a 64 KB per scansione regex
