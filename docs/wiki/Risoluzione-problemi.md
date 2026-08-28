# Risoluzione problemi

## Windows

### `python` non riconosciuto

- Reinstalla Python spuntando **Add python.exe to PATH**
- Oppure usa `py` al posto di `python`:

```powershell
py -m venv .venv
py -m pip install -e ".[gui]"
```

### Errore ExecutionPolicy su Activate.ps1

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Oppure usa `cmd.exe` con `.venv\Scripts\activate.bat`.

### `pip install` fallisce con errore SSL

```powershell
python -m pip install --upgrade pip certifi
pip install -e ".[gui]"
```

### La GUI non si apre nel browser

Verifica che il terminale mostri `Running on local URL: http://127.0.0.1:7860`.

Apri manualmente quel URL. Controlla che nessun firewall blocchi la porta 7860 in locale.

### Porta 7860 già in uso

Chiudi l'altra istanza Gradio o termina il processo Python precedente.

---

## Formato input

### «Formato non riconosciuto»

- JSON: deve iniziare con `{` senza testo prima/dopo
- CEF: deve contenere `CEF:`
- Email: almeno 2 header tra From, Received, Message-ID, Subject, …
- IOC: ogni token deve essere IP/hash/URL/dominio valido

### Email «non classificabile»

Header insufficienti. Incolla l'intero blocco «Mostra originale» con From, Received e Message-ID.

---

## OSINT

### Nessun arricchimento / tutti «non verificato»

- Verifica che `.env` esista nella root del progetto
- Controlla che le chiavi non abbiano spazi o virgolette extra
- Riavvia la GUI/CLI dopo aver modificato `.env`

### Errori 429 (rate limit)

Riduci `VT_REQUESTS_PER_MINUTE` a 4 o attendi qualche minuto.

### Cache non aggiorna

Gli **IP non sono mai cachati**. Per hash/URL usa `--no-cache` per forzare lookup live.

---

## Prestazioni

### Analisi email lenta

L'estrazione generica su centinaia di domini negli header è disabilitata. Se l'input è enorme, riduci il testo incollato.

### Troppi IOC estratti

Errore `Troppi IOC estratti`: aumenta `DECODER_MAX_ARTIFACTS` o riduci l'input.

---

## Supporto

- Repository: https://github.com/DarkGreen-projects/Decoder_SIEMjson
- Apri una **Issue** su GitHub per bug o richieste
