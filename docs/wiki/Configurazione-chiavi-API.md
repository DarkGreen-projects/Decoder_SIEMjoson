# Configurazione chiavi API

Decoder SIEM può funzionare **senza chiavi** (solo estrazione IOC). Per l'arricchimento OSINT configura un file `.env` nella root del progetto.

## Creare il file .env

```bash
cp .env.example .env
```

Su Windows:

```powershell
copy .env.example .env
```

---

## Servizi supportati

| Servizio | Variabile | Registrazione | Note |
|----------|-----------|---------------|------|
| VirusTotal | `VT_API_KEY` | https://www.virustotal.com/gui/my-apikey | Free tier ~4 req/min |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | https://www.abuseipdb.com/account/api | ~1000 check/giorno |
| AlienVault OTX | `OTX_API_KEY` | https://otx.alienvault.com → Settings → API | Gratuito |
| URLhaus | `URLHAUS_AUTH_KEY` | https://auth.abuse.ch/ | Auth-Key gratuita obbligatoria |

---

## Esempio .env completo

```env
VT_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
VT_REQUESTS_PER_MINUTE=4

ABUSEIPDB_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
ABUSEIPDB_MAX_AGE_DAYS=90

OTX_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

URLHAUS_AUTH_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

OSINT_REQUESTS_PER_MINUTE=30

# Cache SQLite (opzionale)
ENRICHMENT_CACHE_ENABLED=true
ENRICHMENT_CACHE_TTL_HOURS=24
# ENRICHMENT_CACHE_PATH=C:\Users\TuoiUser\.local\share\decoder_siem\enrichment_cache.db
```

---

## Rate limit consigliati

- **VirusTotal free**: `VT_REQUESTS_PER_MINUTE=4`
- **Altri enricher**: `OSINT_REQUESTS_PER_MINUTE=30`

Superare i limiti può causare errori 429 (too many requests) temporanei.

---

## Sicurezza

- Non committare mai il file `.env` (è in `.gitignore`)
- Non condividere le chiavi in chat o ticket
- Ruota le chiavi se esposte accidentalmente
