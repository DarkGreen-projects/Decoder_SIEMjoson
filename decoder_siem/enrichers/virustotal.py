from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import vt

from decoder_siem.enrichers.base import Enricher
from decoder_siem.models import (
    Artifact,
    ArtifactScope,
    ArtifactType,
    EnrichmentResult,
    EnrichmentStatus,
)

if TYPE_CHECKING:
    from decoder_siem.enrichment_cache import EnrichmentCacheStore


class VirusTotalEnricher(Enricher):
    name = "virustotal"

    def __init__(
        self,
        api_key: str,
        *,
        requests_per_minute: int = 4,
        cache_store: EnrichmentCacheStore | None = None,
    ) -> None:
        self._client = vt.Client(api_key)
        self._min_interval = 60.0 / max(requests_per_minute, 1)
        self._last_request = 0.0
        self._cache_store = cache_store

    def close(self) -> None:
        self._client.close()

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
        if artifact.scope == ArtifactScope.INTERNAL:
            return EnrichmentResult(
                enricher=self.name,
                status=EnrichmentStatus.SKIPPED,
                summary="IP interno: lookup VirusTotal non applicabile",
            )

        if self._cache_store is not None:
            cached = self._cache_store.get(self.name, artifact)
            if cached is not None:
                return cached

        try:
            data = self._lookup(artifact)
            result = EnrichmentResult(
                enricher=self.name,
                status=EnrichmentStatus.SUCCESS,
                summary=self._build_summary(data),
                data=data,
            )
            if self._cache_store is not None:
                self._cache_store.put(self.name, artifact, result)
            return result
        except vt.APIError as exc:
            if getattr(exc, "code", "") == "NotFoundError":
                result = EnrichmentResult(
                    enricher=self.name,
                    status=EnrichmentStatus.NOT_FOUND,
                    summary="IOC non presente in VirusTotal",
                    error=str(exc),
                )
                if self._cache_store is not None:
                    self._cache_store.put(self.name, artifact, result)
                return result
            result = EnrichmentResult(
                enricher=self.name,
                status=EnrichmentStatus.ERROR,
                summary="Errore API VirusTotal",
                error=str(exc),
            )
            if self._cache_store is not None:
                self._cache_store.put(self.name, artifact, result)
            return result
        except Exception as exc:  # noqa: BLE001
            result = EnrichmentResult(
                enricher=self.name,
                status=EnrichmentStatus.ERROR,
                summary="Errore durante l'arricchimento",
                error=str(exc),
            )
            if self._cache_store is not None:
                self._cache_store.put(self.name, artifact, result)
            return result

    def _lookup(self, artifact: Artifact) -> dict[str, Any]:
        self._throttle()
        if artifact.type in (
            ArtifactType.HASH_SHA256,
            ArtifactType.HASH_SHA1,
            ArtifactType.HASH_MD5,
        ):
            obj = self._get_with_retry(f"/files/{artifact.normalized_value}")
            return self._format_file(obj)
        if artifact.type == ArtifactType.IP:
            obj = self._get_with_retry(f"/ip_addresses/{artifact.normalized_value}")
            return self._format_ip(obj)
        if artifact.type == ArtifactType.DOMAIN:
            obj = self._get_with_retry(f"/domains/{artifact.normalized_value}")
            return self._format_domain(obj)
        if artifact.type == ArtifactType.URL:
            url_id = vt.url_id(artifact.normalized_value)
            obj = self._get_with_retry(f"/urls/{url_id}")
            return self._format_url(obj)
        raise ValueError(f"Tipo non supportato: {artifact.type}")

    def _get_with_retry(self, path: str, max_retries: int = 3) -> vt.Object:
        delay = 2.0
        for attempt in range(max_retries + 1):
            try:
                self._throttle()
                return self._client.get_object(path)
            except vt.APIError as exc:
                code = getattr(exc, "code", "")
                if code in ("QuotaExceededError", "TooManyRequestsError") and attempt < max_retries:
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise
        raise vt.APIError("Max retries exceeded")

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.monotonic()

    def _format_file(self, obj: vt.Object) -> dict[str, Any]:
        stats = obj.get("last_analysis_stats") or {}
        total = sum(stats.values()) or 1
        malicious = stats.get("malicious", 0)
        return {
            "type": "file",
            "sha256": obj.get("sha256"),
            "meaningful_name": obj.get("meaningful_name"),
            "type_tag": obj.get("type_tag"),
            "last_analysis_stats": stats,
            "detection_ratio": f"{malicious}/{total}",
            "last_analysis_date": obj.get("last_analysis_date"),
            "permalink": f"https://www.virustotal.com/gui/file/{obj.get('sha256') or obj.id}",
        }

    def _format_ip(self, obj: vt.Object) -> dict[str, Any]:
        stats = obj.get("last_analysis_stats") or {}
        total = sum(stats.values()) or 1
        malicious = stats.get("malicious", 0)
        return {
            "type": "ip",
            "country": obj.get("country"),
            "as_owner": obj.get("as_owner"),
            "last_analysis_stats": stats,
            "detection_ratio": f"{malicious}/{total}",
            "permalink": f"https://www.virustotal.com/gui/ip-address/{obj.id}",
        }

    def _format_domain(self, obj: vt.Object) -> dict[str, Any]:
        stats = obj.get("last_analysis_stats") or {}
        total = sum(stats.values()) or 1
        malicious = stats.get("malicious", 0)
        return {
            "type": "domain",
            "last_analysis_stats": stats,
            "detection_ratio": f"{malicious}/{total}",
            "permalink": f"https://www.virustotal.com/gui/domain/{obj.id}",
        }

    def _format_url(self, obj: vt.Object) -> dict[str, Any]:
        stats = obj.get("last_analysis_stats") or {}
        total = sum(stats.values()) or 1
        malicious = stats.get("malicious", 0)
        return {
            "type": "url",
            "url": obj.get("url"),
            "last_analysis_stats": stats,
            "detection_ratio": f"{malicious}/{total}",
            "permalink": f"https://www.virustotal.com/gui/url/{obj.id}",
        }

    def _build_summary(self, data: dict[str, Any]) -> str:
        ratio = data.get("detection_ratio", "N/A")
        kind = data.get("type", "unknown")
        if kind == "file":
            name = data.get("meaningful_name") or data.get("sha256", "")
            return f"File {name}: rilevazioni {ratio}"
        if kind == "ip":
            country = data.get("country") or "?"
            return f"IP {data.get('permalink', '')}: {ratio}, paese {country}"
        return f"{kind}: rilevazioni {ratio}"
