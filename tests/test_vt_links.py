from decoder_siem.models import (
    Artifact,
    ArtifactReport,
    ArtifactScope,
    ArtifactType,
    EnrichmentResult,
    EnrichmentStatus,
)
from decoder_siem.table_export import report_to_colored_html, report_to_rows, vt_permalink


def test_vt_permalink_hash():
    ar = ArtifactReport(
        artifact=Artifact(
            type=ArtifactType.HASH_SHA256,
            value="abc" * 21 + "a",
            normalized_value="A" * 64,
            scope=ArtifactScope.PUBLIC,
        )
    )
    link = vt_permalink(ar)
    assert link is not None
    assert "/gui/file/" in link
    assert "A" * 64 in link


def test_vt_permalink_from_enrichment():
    ar = ArtifactReport(
        artifact=Artifact(
            type=ArtifactType.URL,
            value="https://example.com/x",
            normalized_value="https://example.com/x",
        ),
        enrichments=[
            EnrichmentResult(
                enricher="virustotal",
                status=EnrichmentStatus.SUCCESS,
                data={"permalink": "https://www.virustotal.com/gui/url/abc123"},
            )
        ],
    )
    assert vt_permalink(ar) == "https://www.virustotal.com/gui/url/abc123"


def test_colored_html_has_anchor_for_hash():
    from decoder_siem.pipeline import build_report_from_text
    from pathlib import Path

    text = Path(__file__).parent / "fixtures" / "cynet_malicious_pdf.json"
    report = build_report_from_text(text.read_text(encoding="utf-8"), enrich=False)
    html_out = report_to_colored_html(report)
    assert 'href="https://www.virustotal.com/gui/file/' in html_out


def test_rows_include_link_column():
    from decoder_siem.pipeline import build_report_from_text
    from pathlib import Path
    from decoder_siem.table_export import TABLE_HEADERS

    text = Path(__file__).parent / "fixtures" / "defender_ldap_recon.json"
    report = build_report_from_text(text.read_text(encoding="utf-8"), enrich=False)
    rows = report_to_rows(report)
    assert len(TABLE_HEADERS) == 11
    vt_link_idx = TABLE_HEADERS.index("Link VT")
    assert any(
        row[vt_link_idx].startswith("https://")
        for row in rows
        if row[vt_link_idx] != "-"
    )
