from pathlib import Path
from unittest.mock import patch

import pytest

from decoder_siem.correlation import (
    build_correlated_entities,
    entity_role_label,
    should_skip_enrichment,
)
from decoder_siem.enrichment_config import EnrichmentConfig
from decoder_siem.extractors.cynet import CynetExtractor
from decoder_siem.extractors.microsoft_defender import MicrosoftDefenderExtractor
from decoder_siem.models import ArtifactReport, ArtifactType, EnrichmentStatus
from decoder_siem.parser import prepare_incident_data
from decoder_siem.pipeline import build_report_from_text
from decoder_siem.table_export import enrichment_by_name

CYNET_FIXTURE = Path(__file__).parent / "fixtures" / "cynet_malicious_pdf.json"
DEFENDER_FIXTURE = Path(__file__).parent / "fixtures" / "defender_malware_file.json"

INFECTED_SHA = "553C792B1B8F98D7BCD59267B4D5FF7755CBCE019597DD8EBAD4AFE1A00CAC8D"
PROCESS_SHA = "B1EF03497D6823CE6D8BC77D6EF8BDC4A21FF560AD7A613D539C9851BECF2405"
FILE_SHA = "A1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF123456"
PROC_SHA = "FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321"


@pytest.fixture
def cynet_block():
    _, vendor, block = prepare_incident_data(CYNET_FIXTURE)
    assert vendor == "Cynet"
    return block


def test_cynet_artifacts_have_correlation_context(cynet_block):
    artifacts = CynetExtractor().extract(cynet_block)
    infected_hashes = [
        a
        for a in artifacts
        if a.type == ArtifactType.HASH_SHA256
        and a.normalized_value == INFECTED_SHA
    ]
    assert infected_hashes
    assert infected_hashes[0].context.get("correlation_group")
    assert infected_hashes[0].context.get("entity_role") == "infected_file"

    paths = [a for a in artifacts if a.type == ArtifactType.FILE_PATH]
    primary_paths = [
        a for a in paths if a.context.get("entity_role") == "infected_file"
    ]
    assert primary_paths
    assert primary_paths[0].context.get("correlation_group")


def test_build_correlated_entities_cynet(cynet_block):
    artifacts = CynetExtractor().extract(cynet_block)
    reports = [ArtifactReport(artifact=a) for a in artifacts]
    entities = build_correlated_entities(reports)

    infected = [e for e in entities if e.role == "infected_file" and e.hash_artifact]
    assert infected
    assert any(
        e.hash_artifact and e.hash_artifact.normalized_value == INFECTED_SHA
        for e in infected
    )
    assert any(e.path_artifact for e in infected)

    process_entities = [
        e for e in entities if e.role in ("parent_process", "grandparent_process")
    ]
    assert len(process_entities) >= 2


def test_should_skip_path_when_hash_correlated(cynet_block):
    artifacts = CynetExtractor().extract(cynet_block)
    reports = [ArtifactReport(artifact=a) for a in artifacts]
    entities = build_correlated_entities(reports)

    path = next(a for a in artifacts if a.type == ArtifactType.FILE_PATH and a.context.get("entity_role") == "infected_file")
    reason = should_skip_enrichment(path, entities)
    assert reason
    assert "hash correlato" in reason.lower()


def test_defender_file_and_url_correlation():
    _, vendor, block = prepare_incident_data(DEFENDER_FIXTURE)
    assert vendor == "MicrosoftDefender"
    artifacts = MicrosoftDefenderExtractor().extract(block)
    reports = [ArtifactReport(artifact=a) for a in artifacts]
    entities = build_correlated_entities(reports)

    file_hash = next(
        a for a in artifacts if a.normalized_value == FILE_SHA
    )
    file_path = next(
        a for a in artifacts if a.type == ArtifactType.FILE_PATH and "filePath" in a.provenance[0]
    )
    download_url = next(
        a
        for a in artifacts
        if a.type == ArtifactType.URL and a.provenance[0].endswith(".url")
    )

    assert file_hash.context["correlation_group"] == file_path.context["correlation_group"]
    assert download_url.context["correlation_group"] == file_hash.context["correlation_group"]

    assert should_skip_enrichment(file_path, entities)
    assert should_skip_enrichment(download_url, entities)

    proc_hash = next(a for a in artifacts if a.normalized_value == PROC_SHA)
    assert not should_skip_enrichment(proc_hash, entities)


def test_pipeline_skips_correlated_url_enrichment():
    text = DEFENDER_FIXTURE.read_text(encoding="utf-8")
    config = EnrichmentConfig(
        vt_api_key="fake-key",
        osint_requests_per_minute=1000,
    )

    class FakeVTObject:
        def __init__(self, stats: dict[str, int], sha: str | None = None) -> None:
            self._stats = stats
            self.id = sha or "id"

        def get(self, key: str, default=None):
            if key == "last_analysis_stats":
                return self._stats
            if key == "sha256":
                return self.id
            return default

    def fake_vt_get(path, *args, **kwargs):
        if FILE_SHA in path:
            return FakeVTObject({"malicious": 1, "harmless": 0}, FILE_SHA)
        if PROC_SHA in path:
            return FakeVTObject({"malicious": 0, "harmless": 10}, PROC_SHA)
        raise Exception(f"unexpected VT path: {path}")

    with patch(
        "decoder_siem.enrichers.virustotal.VirusTotalEnricher._get_with_retry",
        side_effect=fake_vt_get,
    ):
        report = build_report_from_text(
            text, enrich=True, config=config, requests_per_minute=1000
        )

    url_ar = next(
        ar
        for ar in report.artifacts
        if ar.artifact.type == ArtifactType.URL
        and ar.artifact.provenance[0].endswith(".url")
    )
    corr = enrichment_by_name(url_ar, "correlation")
    assert corr is not None
    assert corr.status == EnrichmentStatus.SKIPPED
    assert not enrichment_by_name(url_ar, "virustotal")

    hash_ars = [
        ar
        for ar in report.artifacts
        if ar.artifact.type == ArtifactType.HASH_SHA256
        and ar.artifact.normalized_value in (FILE_SHA, PROC_SHA)
    ]
    assert len(hash_ars) == 2
    assert all(enrichment_by_name(ar, "virustotal") for ar in hash_ars)

    path_ar = next(
        ar
        for ar in report.artifacts
        if ar.artifact.type == ArtifactType.FILE_PATH
        and "filePath" in ar.artifact.provenance[0]
        and "process" not in ar.artifact.provenance[0]
    )
    assert enrichment_by_name(path_ar, "correlation") is not None

    assert (report.context.extra or {}).get("correlation_skips", 0) >= 2


def test_cynet_pipeline_three_hashes_enriched():
    text = CYNET_FIXTURE.read_text(encoding="utf-8")
    config = EnrichmentConfig(
        vt_api_key="fake-key",
        osint_requests_per_minute=1000,
        cache_enabled=False,
    )

    vt_file_calls: list[str] = []

    class FakeVTObject:
        def __init__(self, sha: str) -> None:
            self.id = sha

        def get(self, key: str, default=None):
            if key == "last_analysis_stats":
                return {"malicious": 0, "harmless": 1}
            if key == "sha256":
                return self.id
            return default

    def fake_vt_get(path, *args, **kwargs):
        if path.startswith("/files/"):
            vt_file_calls.append(path)
            sha = path.rsplit("/", 1)[-1]
            return FakeVTObject(sha)
        raise Exception(f"unexpected VT path: {path}")

    with patch(
        "decoder_siem.enrichers.virustotal.VirusTotalEnricher._get_with_retry",
        side_effect=fake_vt_get,
    ):
        report = build_report_from_text(
            text, enrich=True, config=config, requests_per_minute=1000
        )

    enriched_hashes = {
        ar.artifact.normalized_value
        for ar in report.artifacts
        if ar.artifact.type == ArtifactType.HASH_SHA256
        and enrichment_by_name(ar, "virustotal")
    }
    assert INFECTED_SHA in enriched_hashes
    assert PROCESS_SHA in enriched_hashes
    assert len(enriched_hashes) >= 3
    assert len(vt_file_calls) == len(enriched_hashes)

    infected_path = next(
        ar
        for ar in report.artifacts
        if ar.artifact.type == ArtifactType.FILE_PATH
        and ar.artifact.value == "/Volumes/Public/sample.pdf"
    )
    assert enrichment_by_name(infected_path, "correlation") is not None


def test_entity_role_label():
    assert entity_role_label("infected_file") == "file infetto"
    assert entity_role_label("parent_process") == "proc. padre"
