import pytest

from decoder_siem.enrichment_cache import EnrichmentCacheStore
from decoder_siem.extractors.generic import _make_artifact
from decoder_siem.input_guard import (
    InputSecurityError,
    check_json_depth,
    loads_json_bounded,
    max_input_chars,
    max_ioc_value_len,
    sanitize_markdown_text,
    validate_artifact_value,
    validate_text_input,
)
from decoder_siem.models import Artifact, ArtifactType, EnrichmentResult, EnrichmentStatus
from decoder_siem.pipeline import build_report_from_text


def test_validate_text_rejects_oversized():
    with pytest.raises(InputSecurityError):
        validate_text_input("x" * (max_input_chars() + 1))


def test_validate_text_rejects_nul_byte():
    with pytest.raises(InputSecurityError):
        validate_text_input("hello\x00world")


def test_json_depth_limit_rejects_deep_nesting():
    obj = {"a": None}
    current = obj
    for _ in range(100):
        nxt = {"nested": current}
        current = nxt
    with pytest.raises(InputSecurityError):
        check_json_depth(current)


def test_validate_artifact_value_rejects_long_ioc():
    with pytest.raises(InputSecurityError):
        validate_artifact_value("a" * (max_ioc_value_len() + 1))


def test_make_artifact_validates_value():
    with pytest.raises(InputSecurityError):
        _make_artifact(ArtifactType.DOMAIN, "x" * 5000, "test.path")


def test_sanitize_markdown_escapes_script():
    assert "&lt;script&gt;" in sanitize_markdown_text("<script>alert(1)</script>")
    assert "javascript:" not in sanitize_markdown_text("[x](javascript:alert(1))")


def test_sql_like_value_in_cache_is_parameterized(tmp_path):
    db = tmp_path / "cache.db"
    store = EnrichmentCacheStore(db, ttl_hours=24)
    malicious = "'; DROP TABLE enrichment_cache; --"
    art = Artifact(
        type=ArtifactType.HASH_SHA256,
        value=malicious,
        normalized_value=malicious,
        provenance=["test"],
    )
    result = EnrichmentResult(
        enricher="virustotal",
        status=EnrichmentStatus.SUCCESS,
        summary="ok",
        data={"detection_ratio": "0/1"},
    )
    store.put("virustotal", art, result)
    cached = store.get("virustotal", art)
    assert cached is not None
    assert cached.status == EnrichmentStatus.SUCCESS

    assert store._conn is not None
    tables = store._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='enrichment_cache'"
    ).fetchone()
    assert tables is not None
    store.close()


def test_build_report_rejects_huge_json(monkeypatch):
    monkeypatch.setenv("DECODER_MAX_INPUT_CHARS", "1000")
    huge = "x" * 2000
    with pytest.raises(InputSecurityError):
        build_report_from_text(huge, enrich=False)


def test_context_markdown_sanitizes_xss():
    from decoder_siem.models import IncidentContext
    from decoder_siem.table_export import context_to_markdown

    ctx = IncidentContext(incident_name="<img src=x onerror=alert(1)>")
    md = context_to_markdown(ctx)
    assert "<img" not in md
    assert "&lt;img" in md
