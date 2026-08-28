# Installazione su Windows da zero

Questa guida parte da un PC **Windows 10 o 11** senza Python, Git o altri strumenti di sviluppo installati.

Tempo stimato: 20–40 minuti (inclusa registrazione alle API OSINT opzionali).

---

## Panoramica dei passaggi

1. Installare **Git** (per scaricare il progetto)
2. Installare **Python 3.11+** (motore del programma)
3. Scaricare il repository Decoder SIEM
4. Creare ambiente virtuale e installare dipendenze
5. Configurare il file `.env` (chiavi API opzionali)
6. Avviare la GUI o la CLI

---

## Passo 1 — Installare Git

### Opzione A: sito ufficiale (consigliata)

1. Apri il browser e vai su: https://git-scm.com/download/win
2. Scarica l'installer (64-bit)
3. Esegui l'installer con le opzioni predefinite
4. Al termine, apri **PowerShell** o **Prompt dei comandi** e verifica:

```powershell
git --version
```

Deve comparire qualcosa come `git version 2.x.x`.

### Opzione B: winget (Windows 11 / Windows 10 aggiornato)

Apri **PowerShell** come utente normale:

```powershell
winget install --id Git.Git -e --source winget
```

Chiudi e riapri il terminale, poi verifica con `git --version`.

---

## Passo 2 — Installare Python 3.11 o superiore

### Opzione A: sito ufficiale (consigliata)

1. Vai su: https://www.python.org/downloads/windows/
2. Scarica **Python 3.12** (o 3.11) — installer Windows 64-bit
3. **IMPORTANTE**: nella prima schermata dell'installer, spunta:
   - ✅ **Add python.exe to PATH**
4. Clicca **Install Now** e attendi il completamento
5. Verifica in un nuovo PowerShell:

```powershell
python --version
```

Deve mostrare `Python 3.11.x` o `Python 3.12.x`.

Se `python` non viene riconosciuto, prova:

```powershell
py --version
```

Su Windows il launcher `py` è spesso disponibile anche quando `python` non è nel PATH.

### Opzione B: winget

```powershell
winget install Python.Python.3.12
```

Riapri il terminale e verifica con `python --version`.

---

## Passo 3 — Scaricare Decoder SIEM

Apri **PowerShell** e scegli una cartella di lavoro, ad esempio il Desktop:

```powershell
cd $env:USERPROFILE\Desktop
git clone https://github.com/DarkGreen-projects/Decoder_SIEMjson.git
cd Decoder_SIEMjson
```

Se non hai Git, puoi scaricare lo ZIP da GitHub:

1. Vai su https://github.com/DarkGreen-projects/Decoder_SIEMjson
2. Clicca **Code** → **Download ZIP**
3. Estrai lo ZIP in `C:\Users\<TuoNome>\Desktop\Decoder_SIEMjson`
4. Apri PowerShell in quella cartella:

```powershell
cd $env:USERPROFILE\Desktop\Decoder_SIEMjson
```

---

## Passo 4 — Ambiente virtuale e installazione

Resta nella cartella del progetto (`Decoder_SIEMjson`).

### 4.1 Creare il virtual environment

```powershell
python -m venv .venv
```

Se `python` non funziona, usa:

```powershell
py -m venv .venv
```

### 4.2 Attivare l'ambiente virtuale

```powershell
.venv\Scripts\Activate.ps1
```

Dopo l'attivazione, il prompt mostra `(.venv)` all'inizio della riga.

**Errore "esecuzione di script disabilitata"?** Esegui una sola volta:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Poi riprova `.venv\Scripts\Activate.ps1`.

**Alternativa (Prompt dei comandi cmd.exe):**

```cmd
.venv\Scripts\activate.bat
```

### 4.3 Aggiornare pip e installare il progetto

Con l'ambiente virtuale attivo:

```powershell
python -m pip install --upgrade pip
pip install -e ".[gui]"
```

L'opzione `[gui]` include Gradio per l'interfaccia grafica. Per solo CLI:

```powershell
pip install -e .
```

### 4.4 Verificare l'installazione

```powershell
decoder-siem version
```

Deve stampare la versione (es. `0.1.0`).

---

## Passo 5 — Configurare le chiavi API (opzionale)

L'estrazione IOC funziona **senza chiavi**. Per l'arricchimento OSINT (VirusTotal, AbuseIPDB, ecc.) configura un file `.env`.

### 5.1 Creare il file .env

```powershell
copy .env.example .env
notepad .env
```

Modifica le righe con le tue chiavi. Esempio minimo con VirusTotal:

```env
VT_API_KEY=la_tua_chiave_virustotal
VT_REQUESTS_PER_MINUTE=4
OSINT_REQUESTS_PER_MINUTE=30
```

Vedi la pagina [Configurazione chiavi API](Configurazione-chiavi-API.md) per ottenere ogni chiave gratuitamente.

Salva e chiudi Notepad.

---

## Passo 6 — Avviare Decoder SIEM

### Opzione consigliata: GUI (interfaccia grafica)

Con ambiente virtuale attivo e `.env` configurato:

```powershell
decoder-siem-gui
```

Oppure:

```powershell
python -m decoder_siem.gui
```

Nel terminale comparirà:

```
Running on local URL:  http://127.0.0.1:7860
```

1. Apri il browser (Chrome, Edge, Firefox)
2. Vai su **http://127.0.0.1:7860**
3. Incolla un alert nel campo testo
4. Clicca **Analizza**

Per fermare il server: `Ctrl+C` nel terminale.

### Opzione alternativa: CLI (riga di comando)

Analisi di un file JSON senza GUI:

```powershell
decoder-siem analyze .\tests\fixtures\cynet_malicious_pdf.json -o .\out\report.json
```

Solo estrazione senza API:

```powershell
decoder-siem extract-only .\tests\fixtures\fortigate_shutdown.cef -o .\out\report.json
```

---

## Passo 7 — Uso quotidiano (riepilogo comandi)

Ogni volta che riapri il PC e vuoi usare Decoder SIEM:

```powershell
cd $env:USERPROFILE\Desktop\Decoder_SIEMjson
.venv\Scripts\Activate.ps1
decoder-siem-gui
```

Puoi creare un file `avvia-gui.bat` sul Desktop con:

```bat
@echo off
cd /d "%USERPROFILE%\Desktop\Decoder_SIEMjson"
call .venv\Scripts\activate.bat
decoder-siem-gui
pause
```

Doppio clic sul file `.bat` per avviare la GUI.

---

## Requisiti di sistema

| Componente | Minimo |
|------------|--------|
| OS | Windows 10 64-bit o superiore |
| RAM | 4 GB (8 GB consigliati) |
| Spazio disco | ~500 MB (Python + dipendenze + cache) |
| Rete | Connessione internet per OSINT e installazione |
| Browser | Qualsiasi browser moderno per la GUI |

---

## Prossimi passi

- [Guida GUI](Guida-GUI.md) — come usare l'interfaccia
- [Formati supportati](Formati-supportati.md) — cosa incollare nel campo testo
- [Risoluzione problemi](Risoluzione-problemi.md) — errori frequenti su Windows
