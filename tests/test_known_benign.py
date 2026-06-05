from decoder_siem.enrichment_config import EnrichmentConfig
from decoder_siem.known_benign import is_known_benign_artifact, is_trusted_domain
from decoder_siem.models import Artifact, ArtifactReport, ArtifactType
from decoder_siem.pipeline import _apply_enrichment, build_report_from_text
from decoder_siem.table_export import classify_artifact


def test_trusted_domains():
    assert is_trusted_domain("google.com")
    assert is_trusted_domain("mail.google.com")
    assert is_trusted_domain("outlook.it")
    assert not is_trusted_domain("evil-phish.example")


def test_known_benign_artifact_domain():
    art = Artifact(
        type=ArtifactType.DOMAIN,
        value="google.com",
        normalized_value="google.com",
        provenance=["test"],
    )
    assert is_known_benign_artifact(art)
    ar = ArtifactReport(artifact=art)
    assert classify_artifact(ar) == "benign"


def test_apply_enrichment_skips_trusted_without_api_calls():
    headers = (
        "From: User <user@gmail.com>\n"
        "To: victim@company.local\n"
        "Subject: Test\n"
        "Message-ID: <id@gmail.com>\n"
        "MIME-Version: 1.0\n"
        "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\n"
        "Received: from mail.google.com ([8.8.8.8]) by mx.google.com; "
        "Mon, 2 Jun 2025 10:00:00 +0000\n"
    )
    report = build_report_from_text(headers, enrich=False)
    _apply_enrichment(report, enrich=True, config=EnrichmentConfig())
    google = [
        ar
        for ar in report.artifacts
        if ar.artifact.normalized_value in ("google.com", "gmail.com")
    ]
    assert google
    for ar in google:
        trusted = [e for e in ar.enrichments if e.enricher == "trusted"]
        assert trusted, ar.artifact.normalized_value
        assert trusted[0].summary and "OSINT saltato" in trusted[0].summary
        assert not [e for e in ar.enrichments if e.enricher == "virustotal"]
