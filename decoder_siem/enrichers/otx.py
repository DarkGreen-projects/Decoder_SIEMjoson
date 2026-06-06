from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING, Any
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

if TYPE_CHECKING:
    from decoder_siem.enrichment_cache import EnrichmentCacheStore

OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"


class OTXEnricher(Enricher):
    name = "otx"

    def __init__(
        self,
        api_key: str,
        *,
        requests_per_minute: int = 30,
        cache_store: EnrichmentCacheStore | None = None,
    ) -> None:
        self._api_key = api_key
        self._http = HttpClient(requests_per_minute=requests_per_minute)
        self._cache_store = cache_store

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
        if self._cache_store is not None:
            cached = self._cache_store.get(self.name, artifact)
            if cached is not None:
                return cached

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

        status, data, err = self._http.get_json(url, headers=headers)

        if status == 0:
            result = EnrichmentResult(
                enricher=self.name,
                status=EnrichmentStatus.ERROR,
                summary="Errore di rete OTX",
                error=err,
            )
            if self._cache_store is not None:
                self._cache_store.put(self.name, artifact, result)
            return result
        if status == 404:
            result = EnrichmentResult(
                enricher=self.name,
                status=EnrichmentStatus.NOT_FOUND,
                summary="IOC non presente in OTX",
            )
            if self._cache_store is not None:
                self._cache_store.put(self.name, artifact, result)
            return result
        if status >= 400:
            result = EnrichmentResult(
                enricher=self.name,
                status=EnrichmentStatus.ERROR,
                summary="Errore API OTX",
                error=err or str(status),
            )
            if self._cache_store is not None:
                self._cache_store.put(self.name, artifact, result)
            return result

        formatted = self._format_response(
            indicator_type, indicator_value, data if isinstance(data, dict) else {}
        )
        result = EnrichmentResult(
            enricher=self.name,
            status=EnrichmentStatus.SUCCESS,
            summary=self._build_summary(formatted),
            data=formatted,
        )
        if self._cache_store is not None:
            self._cache_store.put(self.name, artifact, result)
        return result

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
