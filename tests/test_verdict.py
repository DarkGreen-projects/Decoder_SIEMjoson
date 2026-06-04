from decoder_siem.models import (
    Artifact,
    ArtifactReport,
    ArtifactScope,
    ArtifactType,
    EnrichmentResult,
    EnrichmentStatus,
)
from decoder_siem.table_export import (
    COLOR_BENIGN,
    COLOR_MALICIOUS,
    classify_artifact,
    report_to_colored_html,
    verdict_color,
)


def _ar(
    art_type: ArtifactType,
    value: str,
    *,
    scope: ArtifactScope = ArtifactScope.PUBLIC,
    enrichment: EnrichmentResult | None = None,
) -> ArtifactReport:
    art = Artifact(
        type=art_type,
        value=value,
        normalized_value=value,
        scope=scope,
        provenance=["test"],
    )
    enrichments = [enrichment] if enrichment else []
    return ArtifactReport(artifact=art, enrichments=enrichments)


def test_classify_malicious():
    enr = EnrichmentResult(
        enricher="virustotal",
        status=EnrichmentStatus.SUCCESS,
        data={"last_analysis_stats": {"malicious": 5, "harmless": 60, "undetected": 5}},
    )
    ar = _ar(ArtifactType.IP, "8.8.8.8", enrichment=enr)
    assert classify_artifact(ar) == "malicious"
    assert verdict_color("malicious") == COLOR_MALICIOUS


def test_classify_suspicious_as_malicious():
    enr = EnrichmentResult(
        enricher="virustotal",
        status=EnrichmentStatus.SUCCESS,
        data={"last_analysis_stats": {"malicious": 0, "suspicious": 2, "harmless": 70}},
    )
    ar = _ar(ArtifactType.DOMAIN, "evil.example", enrichment=enr)
    assert classify_artifact(ar) == "malicious"


def test_classify_benign_vt_clean():
    enr = EnrichmentResult(
        enricher="virustotal",
        status=EnrichmentStatus.SUCCESS,
        data={"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70}},
    )
    ar = _ar(ArtifactType.IP, "93.184.216.34", enrichment=enr)
    assert classify_artifact(ar) == "benign"
    assert verdict_color("benign") == COLOR_BENIGN


def test_classify_internal_ip_benign():
    enr = EnrichmentResult(
        enricher="virustotal",
        status=EnrichmentStatus.SKIPPED,
        summary="IP interno",
    )
    ar = _ar(
        ArtifactType.IP,
        "192.168.1.1",
        scope=ArtifactScope.INTERNAL,
        enrichment=enr,
    )
    assert classify_artifact(ar) == "benign"


def test_classify_unknown_no_enrichment():
    ar = _ar(ArtifactType.IP, "1.2.3.4")
    assert classify_artifact(ar) == "unknown"


def test_colored_html_contains_colors():
    from decoder_siem.pipeline import build_report_from_text
    from pathlib import Path

    text = Path(__file__).parent / "fixtures" / "defender_ldap_recon.json"
    report = build_report_from_text(text.read_text(encoding="utf-8"), enrich=False)
    html_out = report_to_colored_html(report)
    assert "Elementi analizzati" in html_out
    assert COLOR_BENIGN in html_out or COLOR_MALICIOUS in html_out


def test_gui_run_analysis_signature():
    from decoder_siem.gui import run_analysis

    summary, html_out, rows, err = run_analysis("")
    assert "Inserisci" in err
    assert rows == []
