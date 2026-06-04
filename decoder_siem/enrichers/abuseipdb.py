from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from decoder_siem.enrichers.base import Enricher
from decoder_siem.enrichers.http_client import HttpClient
from decoder_siem.models import (
    Artifact,
    ArtifactScope,
    ArtifactType,
    EnrichmentResult,
    EnrichmentStatus,
)

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
MALICIOUS_SCORE_THRESHOLD = 25


class AbuseIPDBEnricher(Enricher):
    name = "abuseipdb"

    def __init__(
        self,
        api_key: str,
        *,
        max_age_in_days: int = 90,
        requests_per_minute: int = 30,
        cache_dir: Path | None = None,
    ) -> None:
        self._api_key = api_key
        self._max_age = max(1, min(max_age_in_days, 365))
        self._http = HttpClient(
            requests_per_minute=requests_per_minute,
            cache_dir=cache_dir,
        )

    def supports(self, artifact: Artifact) -> bool:
        return (
            artifact.type == ArtifactType.IP
            and artifact.scope == ArtifactScope.PUBLIC
        )

    def enrich(self, artifact: Artifact) -> EnrichmentResult:
        ip = artifact.normalized_value
        params = urlencode(
            {"ipAddress": ip, "maxAgeInDays": str(self._max_age)}
        )
        url = f"{ABUSEIPDB_CHECK_URL}?{params}"
        headers = {
            "Accept": "application/json",
            "Key": self._api_key,
        }
        cache_key = f"abuseipdb_ip_{ip}"
        status, data, err = self._http.get_json(
            url, headers=headers, cache_key=cache_key
        )

        if status == 0:
            return EnrichmentResult(
                enricher=self.name,
                status=EnrichmentStatus.ERROR,
                summary="Errore di rete AbuseIPDB",
                error=err,
            )
        if status == 404 or (isinstance(data, dict) and not data.get("data")):
            return EnrichmentResult(
                enricher=self.name,
                status=EnrichmentStatus.NOT_FOUND,
                summary="IP non presente in AbuseIPDB",
            )
        if status >= 400:
            return EnrichmentResult(
                enricher=self.name,
                status=EnrichmentStatus.ERROR,
                summary="Errore API AbuseIPDB",
                error=err or str(status),
            )

        formatted = self._format_response(ip, data if isinstance(data, dict) else {})
        return EnrichmentResult(
            enricher=self.name,
            status=EnrichmentStatus.SUCCESS,
            summary=self._build_summary(formatted),
            data=formatted,
        )

    def _format_response(self, ip: str, raw: dict[str, Any]) -> dict[str, Any]:
        block = raw.get("data") or {}
        score = block.get("abuseConfidenceScore", 0)
        return {
            "type": "ip",
            "ip": ip,
            "abuse_confidence_score": score,
            "total_reports": block.get("totalReports", 0),
            "country_code": block.get("countryCode"),
            "isp": block.get("isp"),
            "domain": block.get("domain"),
            "is_whitelisted": block.get("isWhitelisted", False),
            "permalink": f"https://www.abuseipdb.com/check/{ip}",
        }

    def _build_summary(self, data: dict[str, Any]) -> str:
        score = data.get("abuse_confidence_score", 0)
        reports = data.get("total_reports", 0)
        return f"AbuseIPDB score {score}% ({reports} segnalazioni)"

    @staticmethod
    def is_malicious(data: dict[str, Any]) -> bool:
        score = data.get("abuse_confidence_score", 0) or 0
        reports = data.get("total_reports", 0) or 0
        if score >= MALICIOUS_SCORE_THRESHOLD:
            return True
        return reports > 0 and score > 0
