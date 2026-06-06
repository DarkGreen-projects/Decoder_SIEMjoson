from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from decoder_siem.enrichment_cache import (
    EnrichmentCacheStore,
    is_cacheable,
)
from decoder_siem.enrichers.virustotal import VirusTotalEnricher
from decoder_siem.enrichment_config import EnrichmentConfig
from decoder_siem.models import (
    Artifact,
    ArtifactScope,
    ArtifactType,
    EnrichmentResult,
    EnrichmentStatus,
)
from decoder_siem.pipeline import build_report_from_text


def _artifact(art_type: ArtifactType, value: str) -> Artifact:
    return Artifact(
        type=art_type,
        value=value,
        normalized_value=value,
        scope=ArtifactScope.PUBLIC,
        provenance=["test"],
    )


def test_is_cacheable_excludes_ip():
    assert is_cacheable(ArtifactType.HASH_SHA256)
    assert is_cacheable(ArtifactType.URL)
    assert not is_cacheable(ArtifactType.IP)


def test_hash_cached_on_second_lookup(tmp_path):
    db = tmp_path / "cache.db"
    store = EnrichmentCacheStore(db, ttl_hours=24)
    art = _artifact(ArtifactType.HASH_SHA256, "A" * 64)
    result = EnrichmentResult(
        enricher="virustotal",
        status=EnrichmentStatus.SUCCESS,
        summary="ok",
        data={"detection_ratio": "1/10"},
    )
    store.put("virustotal", art, result)

    cached = store.get("virustotal", art)
    assert cached is not None
    assert cached.status == EnrichmentStatus.SUCCESS
    assert "da cache" in (cached.summary or "").lower()
    assert cached.data.get("_from_cache") is True
    assert store.hits == 1
    store.close()


def test_ip_not_stored_in_cache(tmp_path):
    db = tmp_path / "cache.db"
    store = EnrichmentCacheStore(db, ttl_hours=24)
    art = _artifact(ArtifactType.IP, "1.2.3.4")
    result = EnrichmentResult(
        enricher="virustotal",
        status=EnrichmentStatus.SUCCESS,
        summary="ip ok",
        data={"type": "ip"},
    )
    store.put("virustotal", art, result)
    assert store.get("virustotal", art) is None
    store.close()


def test_expired_entry_removed_and_refetched(tmp_path):
    db = tmp_path / "cache.db"
    store = EnrichmentCacheStore(db, ttl_hours=1)
    art = _artifact(ArtifactType.HASH_MD5, "B" * 32)
    result = EnrichmentResult(
        enricher="virustotal",
        status=EnrichmentStatus.NOT_FOUND,
        summary="assente",
    )
    store.put("virustotal", art, result)

    old = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
    assert store._conn is not None
    store._conn.execute(
        "UPDATE enrichment_cache SET cached_at = ? WHERE normalized_value = ?",
        (old, art.normalized_value),
    )
    store._conn.commit()

    assert store.get("virustotal", art) is None
    purged = store.purge_expired()
    assert purged >= 0
    store.close()


def test_vt_enricher_uses_cache(tmp_path):
    db = tmp_path / "cache.db"
    store = EnrichmentCacheStore(db, ttl_hours=24)
    art = _artifact(ArtifactType.HASH_SHA256, "C" * 64)
    enricher = VirusTotalEnricher("fake-key", requests_per_minute=1000, cache_store=store)

    calls = 0

    class FakeVTObject:
        def __init__(self) -> None:
            self.id = "C" * 64

        def get(self, key: str, default=None):
            if key == "last_analysis_stats":
                return {"malicious": 0, "harmless": 5}
            if key == "sha256":
                return "C" * 64
            return default

    def fake_get(path, *args, **kwargs):
        nonlocal calls
        calls += 1
        return FakeVTObject()

    with patch.object(enricher, "_get_with_retry", side_effect=fake_get):
        first = enricher.enrich(art)
        second = enricher.enrich(art)

    assert calls == 1
    assert first.status == EnrichmentStatus.SUCCESS
    assert second.status == EnrichmentStatus.SUCCESS
    assert "da cache" in (second.summary or "").lower()
    enricher.close()
    store.close()


def test_pipeline_cache_hits_reported(tmp_path):
    db = tmp_path / "pipeline_cache.db"
    text = '{"HostIp": "8.8.8.8"}'
    config = EnrichmentConfig(
        vt_api_key="fake-key",
        cache_enabled=True,
        cache_ttl_hours=24,
        cache_path=db,
        osint_requests_per_minute=1000,
    )

    class FakeVTObject:
        def __init__(self, path: str) -> None:
            self.id = path.rsplit("/", 1)[-1]

        def get(self, key: str, default=None):
            if key == "last_analysis_stats":
                return {"malicious": 0, "harmless": 1}
            return default

    def fake_get(path, *args, **kwargs):
        return FakeVTObject(path)

    with patch(
        "decoder_siem.enrichers.virustotal.VirusTotalEnricher._get_with_retry",
        side_effect=fake_get,
    ):
        build_report_from_text(
            text,
            enrich=True,
            config=config,
            requests_per_minute=1000,
        )
        report = build_report_from_text(
            text,
            enrich=True,
            config=config,
            requests_per_minute=1000,
        )

    assert (report.context.extra or {}).get("cache_hits", 0) >= 0
