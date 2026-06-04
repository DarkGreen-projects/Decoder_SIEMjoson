from pathlib import Path

from decoder_siem.models import ArtifactScope, ArtifactType
from decoder_siem.parsers.loader import load_document
from decoder_siem.pipeline import build_report

FIXTURE = Path(__file__).parent / "fixtures" / "defender_ldap_recon.json"


def test_load_document_microsoft_defender():
    doc = load_document(FIXTURE)
    assert doc.vendor == "MicrosoftDefender"
    assert doc.format == "json"
    assert doc.vendor_block["detectorId"] == "LdapSearchReconnaissanceSecurityAlert"


def test_defender_context_and_ips():
    report = build_report(FIXTURE, enrich=False)
    assert report.context.vendor == "MicrosoftDefender"
    assert report.context.incident_name == "Security principal reconnaissance (LDAP)"
    assert report.context.event_name == "LdapSearchReconnaissanceSecurityAlert"
    assert report.context.host_name == "NPOTRN2DC11"
    assert report.context.host_ip == "10.12.50.162"

    extra = report.context.extra
    assert "T1087" in extra.get("mitre_techniques", [])
    assert extra.get("severity_text") == "medium"
    assert extra.get("product_name") == "Microsoft Defender for Identity"

    ips = {
        a.artifact.normalized_value: a.artifact.scope
        for a in report.artifacts
        if a.artifact.type == ArtifactType.IP
    }
    assert ips["172.27.38.26"] == ArtifactScope.INTERNAL
    assert ips["10.12.50.162"] == ArtifactScope.INTERNAL
    assert ips["87.241.17.94"] == ArtifactScope.PUBLIC
    assert ips["::1"] == ArtifactScope.INTERNAL

    enrichable_ips = [
        a.artifact.normalized_value
        for a in report.enrichable_artifacts
        if a.artifact.type == ArtifactType.IP
    ]
    assert "87.241.17.94" in enrichable_ips
    assert "172.27.38.26" not in enrichable_ips


def test_defender_domains_and_urls():
    report = build_report(FIXTURE, enrich=False)
    domains = {
        a.artifact.normalized_value
        for a in report.artifacts
        if a.artifact.type == ArtifactType.DOMAIN
    }
    assert "npotrn2dc11.npo-torino.local" in domains

    urls = [a for a in report.artifacts if a.artifact.type == ArtifactType.URL]
    assert any("security.microsoft.com" in a.artifact.value for a in urls)

    hostnames = {
        a.artifact.value
        for a in report.artifacts
        if a.artifact.type == ArtifactType.HOSTNAME
    }
    assert "NPOTRN2DC11" in hostnames


def test_defender_security_groups():
    report = build_report(FIXTURE, enrich=False)
    groups = [
        a.artifact.value
        for a in report.artifacts
        if a.artifact.type == ArtifactType.USERNAME
    ]
    assert "Schema Admins" in groups
    assert "Enterprise Admins" in groups
