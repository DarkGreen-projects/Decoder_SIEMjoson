from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any
from urllib.parse import quote

from decoder_siem.enrichers.base import Enricher
from decoder_siem.enrichers.http_client import HttpClient
from decoder_siem.models import (
    Artifact,
    ArtifactScope,
    ArtifactType,
    EnrichmentResult,
    EnrichmentStatus,
)

OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"


class OTXEnricher(Enricher):
    name = "otx"

    def __init__(
        self,
        api_key: str,
        *,
        requests_per_minute: int = 30,
        cache_dir: Path | None = None,
    ) -> None:
        self._api_key = api_key
        self._http = HttpClient(
            requests_per_minute=requests_per_minute,
            cache_dir=cache_dir,
        )

    def supports(self, artifact: Artifact) -> bool:
        if artifact.scope == ArtifactScope.INTERNAL:
            return False
        return artifact.type in (
            ArtifactType.IP,
            ArtifactType.HASH_SHA256,
            ArtifactType.HASH_SHA1,
            ArtifactType.HASH_MD5,
            ArtifactType.DOMAIN,
            ArtifactType.URL,
        )

    def enrich(self, artifact: Artifact) -> EnrichmentResult:
        indicator_type, indicator_value = self._indicator_for(artifact)
        if not indicator_type:
            return EnrichmentResult(
                enricher=self.name,
                status=EnrichmentStatus.SKIPPED,
                summary="Tipo IOC non supportato da OTX",
            )

        encoded = quote(indicator_value, safe="")
        url = f"{OTX_BASE}/{indicator_type}/{encoded}/general"
        headers = {"X-OTX-API-KEY": self._api_key}
        cache_key = f"otx_{indicator_type}_{artifact.normalized_value}"

        status, data, err = self._http.get_json(
            url, headers=headers, cache_key=cache_key
        )

        if status == 0:
            return EnrichmentResult(
                enricher=self.name,
                status=EnrichmentStatus.ERROR,
                summary="Errore di rete OTX",
                error=err,
            )
        if status == 404:
            return EnrichmentResult(
                enricher=self.name,
                status=EnrichmentStatus.NOT_FOUND,
                summary="IOC non presente in OTX",
            )
        if status >= 400:
            return EnrichmentResult(
                enricher=self.name,
                status=EnrichmentStatus.ERROR,
                summary="Errore API OTX",
                error=err or str(status),
            )

        formatted = self._format_response(
            indicator_type, indicator_value, data if isinstance(data, dict) else {}
        )
        return EnrichmentResult(
            enricher=self.name,
            status=EnrichmentStatus.SUCCESS,
            summary=self._build_summary(formatted),
            data=formatted,
        )

    def _indicator_for(self, artifact: Artifact) -> tuple[str | None, str]:
        val = artifact.normalized_value
        if artifact.type == ArtifactType.IP:
            try:
                addr = ipaddress.ip_address(val)
                return ("IPv6" if addr.version == 6 else "IPv4"), val
            except ValueError:
                return None, val
        if artifact.type in (
            ArtifactType.HASH_SHA256,
            ArtifactType.HASH_SHA1,
            ArtifactType.HASH_MD5,
        ):
            return "file", val
        if artifact.type == ArtifactType.DOMAIN:
            return "domain", val
        if artifact.type == ArtifactType.URL:
            return "url", val
        return None, val

    def _format_response(
        self,
        indicator_type: str,
        indicator_value: str,
        raw: dict[str, Any],
    ) -> dict[str, Any]:
        pulse_info = raw.get("pulse_info") or {}
        pulse_count = pulse_info.get("count", 0)
        if isinstance(pulse_count, str):
            try:
                pulse_count = int(pulse_count)
            except ValueError:
                pulse_count = 0

        permalink = (
            f"https://otx.alienvault.com/indicator/{indicator_type}/"
            f"{quote(indicator_value, safe='')}"
        )
        return {
            "type": indicator_type.lower(),
            "indicator": indicator_value,
            "pulse_count": pulse_count,
            "reputation": raw.get("reputation"),
            "country_name": raw.get("country_name"),
            "validation": raw.get("validation"),
            "permalink": permalink,
        }

    def _build_summary(self, data: dict[str, Any]) -> str:
        pulses = data.get("pulse_count", 0)
        return f"OTX: {pulses} pulse"

    @staticmethod
    def is_malicious(data: dict[str, Any]) -> bool:
        return (data.get("pulse_count") or 0) > 0
