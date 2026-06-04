from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from decoder_siem.enrichers.base import Enricher
from decoder_siem.enrichers.http_client import HttpClient
from decoder_siem.models import (
    Artifact,
    ArtifactScope,
    ArtifactType,
    EnrichmentResult,
    EnrichmentStatus,
)

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1"


class URLhausEnricher(Enricher):
    name = "urlhaus"

    def __init__(
        self,
        auth_key: str,
        *,
        requests_per_minute: int = 30,
        cache_dir: Path | None = None,
    ) -> None:
        self._auth_key = auth_key
        self._http = HttpClient(
            requests_per_minute=requests_per_minute,
            cache_dir=cache_dir,
        )

    def supports(self, artifact: Artifact) -> bool:
        if artifact.scope == ArtifactScope.INTERNAL:
            return False
        return artifact.type in (
            ArtifactType.URL,
            ArtifactType.DOMAIN,
            ArtifactType.IP,
            ArtifactType.HASH_SHA256,
            ArtifactType.HASH_SHA1,
            ArtifactType.HASH_MD5,
        )

    def enrich(self, artifact: Artifact) -> EnrichmentResult:
        headers = {"Auth-Key": self._auth_key}
        art_type = artifact.type
        val = artifact.normalized_value

        if art_type == ArtifactType.URL:
            return self._query_url(val, headers)
        if art_type == ArtifactType.DOMAIN:
            return self._query_host(val, headers)
        if art_type == ArtifactType.IP:
            return self._query_host(val, headers)
        if art_type in (
            ArtifactType.HASH_SHA256,
            ArtifactType.HASH_SHA1,
            ArtifactType.HASH_MD5,
        ):
            return self._query_payload(art_type, val, headers)

        return EnrichmentResult(
            enricher=self.name,
            status=EnrichmentStatus.SKIPPED,
            summary="Tipo non supportato da URLhaus",
        )

    def _query_url(self, url: str, headers: dict[str, str]) -> EnrichmentResult:
        cache_key = f"urlhaus_url_{url}"
        status, data, err = self._http.post_form_json(
            f"{URLHAUS_API}/url/",
            {"url": url},
            headers=headers,
            cache_key=cache_key,
        )
        return self._parse_response(status, data, err, default_host=urlparse(url).hostname)

    def _query_host(self, host: str, headers: dict[str, str]) -> EnrichmentResult:
        cache_key = f"urlhaus_host_{host}"
        status, data, err = self._http.post_form_json(
            f"{URLHAUS_API}/host/",
            {"host": host},
            headers=headers,
            cache_key=cache_key,
        )
        return self._parse_response(status, data, err, default_host=host)

    def _query_payload(
        self,
        art_type: ArtifactType,
        hash_val: str,
        headers: dict[str, str],
    ) -> EnrichmentResult:
        form: dict[str, str]
        if art_type == ArtifactType.HASH_MD5:
            form = {"md5_hash": hash_val}
        else:
            form = {"sha256_hash": hash_val}
        cache_key = f"urlhaus_hash_{hash_val}"
        status, data, err = self._http.post_form_json(
            f"{URLHAUS_API}/payload/",
            form,
            headers=headers,
            cache_key=cache_key,
        )
        return self._parse_response(status, data, err)

    def _parse_response(
        self,
        http_status: int,
        data: dict[str, Any] | list[Any] | None,
        err: str | None,
        *,
        default_host: str | None = None,
    ) -> EnrichmentResult:
        if http_status == 0:
            return EnrichmentResult(
                enricher=self.name,
                status=EnrichmentStatus.ERROR,
                summary="Errore di rete URLhaus",
                error=err,
            )
        if not isinstance(data, dict):
            return EnrichmentResult(
                enricher=self.name,
                status=EnrichmentStatus.ERROR,
                summary="Errore API URLhaus",
                error=err or str(http_status),
            )

        query_status = data.get("query_status", "")
        if query_status == "no_results":
            return EnrichmentResult(
                enricher=self.name,
                status=EnrichmentStatus.NOT_FOUND,
                summary="IOC non presente in URLhaus",
            )
        if query_status != "ok":
            return EnrichmentResult(
                enricher=self.name,
                status=EnrichmentStatus.ERROR,
                summary=f"URLhaus: {query_status or 'errore'}",
                error=err,
            )

        formatted = self._format_response(data, default_host=default_host)
        return EnrichmentResult(
            enricher=self.name,
            status=EnrichmentStatus.SUCCESS,
            summary=self._build_summary(formatted),
            data=formatted,
        )

    def _format_response(
        self,
        raw: dict[str, Any],
        *,
        default_host: str | None = None,
    ) -> dict[str, Any]:
        url_count = raw.get("url_count")
        if url_count is not None:
            try:
                url_count = int(url_count)
            except (TypeError, ValueError):
                url_count = 0

        tags = raw.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]

        return {
            "query_status": raw.get("query_status"),
            "url_status": raw.get("url_status"),
            "host": raw.get("host") or default_host,
            "url_count": url_count,
            "signature": raw.get("signature"),
            "threat": raw.get("threat"),
            "tags": tags,
            "urlhaus_reference": raw.get("urlhaus_reference"),
            "blacklists": raw.get("blacklists"),
        }

    def _build_summary(self, data: dict[str, Any]) -> str:
        status = data.get("url_status")
        if status:
            return f"URLhaus: {status}"
        url_count = data.get("url_count")
        if url_count:
            return f"URLhaus: {url_count} URL"
        sig = data.get("signature")
        if sig:
            return f"URLhaus: {sig}"
        return "URLhaus: presente"

    @staticmethod
    def is_malicious(data: dict[str, Any]) -> bool:
        if data.get("query_status") != "ok":
            return False
        if data.get("url_status") == "online":
            return True
        url_count = data.get("url_count") or 0
        if url_count and int(url_count) > 0:
            return True
        if data.get("signature"):
            return True
        return False
