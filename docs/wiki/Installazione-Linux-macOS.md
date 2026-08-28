# Installazione Linux e macOS

## Requisiti

- Python 3.11 o superiore
- Git

### Debian / Ubuntu

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
```

### Fedora

```bash
sudo dnf install python3 python3-pip git
```

### macOS (Homebrew)

```bash
brew install python@3.12 git
```

---

## Installazione

```bash
git clone https://github.com/DarkGreen-projects/Decoder_SIEMjson.git
cd Decoder_SIEMjson
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[gui]"
cp .env.example .env
# Modifica .env con le tue chiavi API
decoder-siem-gui
```

Apri **http://127.0.0.1:7860** nel browser.

---

## Avvio rapido CLI

```bash
decoder-siem analyze ./tests/fixtures/cynet_malicious_pdf.json -o ./out/report.json
```

Per sviluppo e test:

```bash
pip install -e ".[dev]"
pytest -q
```
