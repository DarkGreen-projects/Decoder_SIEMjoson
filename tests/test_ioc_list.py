from unittest.mock import patch

import pytest

from decoder_siem.enrichment_cache import EnrichmentCacheStore
from decoder_siem.enrichment_config import EnrichmentConfig
from decoder_siem.models import ArtifactScope, ArtifactType
from decoder_siem.parsers.ioc_list import (
    artifacts_from_ioc_tokens,
    classify_ioc_token,
    looks_like_ioc_list,
    tokenize_ioc_input,
)
from decoder_siem.parsers.loader import load_text
from decoder_siem.pipeline import build_report_from_text

SHA256_A = "a" * 64
SHA256_B = "b" * 64
SHA256_C = "c" * 64
SHA1_VAL = "d" * 40


def test_tokenize_ioc_input():
    assert tokenize_ioc_input("1.2.3.4, abc") == ["1.2.3.4", "abc"]
    assert tokenize_ioc_input(f"{SHA256_A} {SHA256_B}") == [SHA256_A, SHA256_B]
    assert tokenize_ioc_input(f"{SHA256_A};{SHA256_B}") == [SHA256_A, SHA256_B]


def test_load_text_single_sha256():
    doc = load_text(SHA256_A)
    assert doc.format == "ioc"
    assert doc.vendor == "RawIOC"
    assert doc.data["tokens"] == [SHA256_A]


def test_load_text_single_ip():
    doc = load_text("8.8.8.8")
    assert doc.format == "ioc"
    artifacts = artifacts_from_ioc_tokens(doc.data["tokens"])
    assert len(artifacts) == 1
    assert artifacts[0].type == ArtifactType.IP
    assert artifacts[0].scope == ArtifactScope.PUBLIC


def test_load_text_private_ip():
    doc = load_text("192.168.1.10")
    artifacts = artifacts_from_ioc_tokens(doc.data["tokens"])
    assert artifacts[0].scope == ArtifactScope.INTERNAL


def test_load_text_ip_and_sha256():
    text = f"8.8.8.8, {SHA256_A}"
    doc = load_text(text)
    artifacts = artifacts_from_ioc_tokens(doc.data["tokens"])
    assert len(artifacts) == 2
    types = {a.type for a in artifacts}
    assert ArtifactType.IP in types
    assert ArtifactType.HASH_SHA256 in types


def test_load_text_multiple_sha_space():
    text = f"{SHA256_A} {SHA256_B} {SHA256_C}"
    doc = load_text(text)
    artifacts = artifacts_from_ioc_tokens(doc.data["tokens"])
    assert len(artifacts) == 3


def test_load_text_deduplicates_repeated_sha():
    text = f"{SHA256_A} {SHA256_A}"
    doc = load_text(text)
    artifacts = artifacts_from_ioc_tokens(doc.data["tokens"])
    assert len(artifacts) == 1


def test_load_text_rejects_mixed_non_ioc():
    with pytest.raises(ValueError, match="Formato non riconosciuto"):
        load_text("hello 1.2.3.4")


def test_classify_sha1():
    art = classify_ioc_token(SHA1_VAL)
    assert art is not None
    assert art.type == ArtifactType.HASH_SHA1


def test_build_report_from_text_raw_ioc():
    report = build_report_from_text(f"8.8.8.8, {SHA256_A}", enrich=False)
    assert report.context.vendor == "RawIOC"
    assert report.context.log_format == "ioc"
    assert len(report.artifacts) == 2


def test_pipeline_cache_with_raw_ioc_hash(tmp_path):
    db = tmp_path / "ioc_cache.db"
    text = SHA256_A
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
        build_report_from_text(text, enrich=True, config=config, requests_per_minute=1000)
        report = build_report_from_text(
            text, enrich=True, config=config, requests_per_minute=1000
        )

    hash_reports = [
        ar for ar in report.artifacts if ar.artifact.type == ArtifactType.HASH_SHA256
    ]
    assert len(hash_reports) == 1
    vt_results = [e for e in hash_reports[0].enrichments if e.enricher == "virustotal"]
    assert vt_results
    assert "da cache" in (vt_results[0].summary or "").lower()


def test_ip_not_cached_with_raw_ioc(tmp_path):
    db = tmp_path / "ioc_ip_cache.db"
    store = EnrichmentCacheStore(db, ttl_hours=24)
    art = classify_ioc_token("8.8.8.8")
    assert art is not None
    from decoder_siem.models import EnrichmentResult, EnrichmentStatus

    store.put(
        "virustotal",
        art,
        EnrichmentResult(
            enricher="virustotal",
            status=EnrichmentStatus.SUCCESS,
            summary="ip ok",
            data={"type": "ip"},
        ),
    )
    assert store.get("virustotal", art) is None
    store.close()


def test_looks_like_ioc_list_false_for_json():
    assert not looks_like_ioc_list('{"Cynet": {}}')
