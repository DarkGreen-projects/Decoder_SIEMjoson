from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class EnrichmentConfig:
    vt_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    otx_api_key: str | None = None
    urlhaus_auth_key: str | None = None
    vt_requests_per_minute: int = 4
    osint_requests_per_minute: int = 30
    abuseipdb_max_age_days: int = 90

    @classmethod
    def from_env(cls) -> EnrichmentConfig:
        return cls(
            vt_api_key=os.getenv("VT_API_KEY") or None,
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY") or None,
            otx_api_key=os.getenv("OTX_API_KEY") or None,
            urlhaus_auth_key=os.getenv("URLHAUS_AUTH_KEY") or None,
            vt_requests_per_minute=int(os.getenv("VT_REQUESTS_PER_MINUTE", "4")),
            osint_requests_per_minute=int(os.getenv("OSINT_REQUESTS_PER_MINUTE", "30")),
            abuseipdb_max_age_days=int(os.getenv("ABUSEIPDB_MAX_AGE_DAYS", "90")),
        )

    def has_any_enricher(self) -> bool:
        return bool(
            self.vt_api_key
            or self.abuseipdb_api_key
            or self.otx_api_key
            or self.urlhaus_auth_key
        )
