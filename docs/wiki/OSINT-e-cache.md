# OSINT e cache

## Fonti OSINT

Per ogni IOC pubblico la pipeline interroga (se configurato):

1. **URLhaus** — URL/host/hash malevoli (abuse.ch)
2. **AbuseIPDB** — reputation IP
3. **AlienVault OTX** — threat intel pulses
4. **VirusTotal** — detection ratio e permalink

Il verdetto è **aggregato**: basta una fonte che segnali minaccia per colorare l'IOC in rosso.

---

## Cosa viene arricchito

| Tipo IOC | VT | AbuseIPDB | OTX | URLhaus | Cache |
|----------|-----|-----------|-----|---------|-------|
| IP pubblico | Sì | Sì | Sì | — | No (sempre live) |
| Hash | Sì | — | Sì | Sì | Sì (24h) |
| URL | Sì | — | Sì | Sì | Sì (24h) |
| Dominio | Sì | — | Sì | Sì | Sì (24h) |
| IP interno | No | No | No | No | — |

---

## Cache SQLite

- **Attiva di default**
- TTL: **24 ore** (`ENRICHMENT_CACHE_TTL_HOURS`)
- Percorso default:
  - Windows: `C:\Users\<user>\.local\share\decoder_siem\enrichment_cache.db`
  - Linux/macOS: `~/.local/share/decoder_siem/enrichment_cache.db`
- Hash/URL/domini già visti non ripetono chiamate API

Disabilitare:

```bash
decoder-siem analyze file.json --no-cache
```

---

## Correlazione XDR

Negli alert Microsoft Defender, path e URL correlati a un hash già nell'evento possono essere esclusi da lookup VT ridondanti.

---

## Infrastrutture note

Domini di provider legittimi (Google, Microsoft, CDN, …) sono etichettati come benigni: link VT disponibili senza chiamate API automatiche superflue.
