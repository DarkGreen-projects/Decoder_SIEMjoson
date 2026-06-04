from pathlib import Path

from decoder_siem.models import ArtifactScope, ArtifactType
from decoder_siem.parsers.loader import load_document
from decoder_siem.pipeline import build_report

SHUTDOWN = Path(__file__).parent / "fixtures" / "fortigate_shutdown.cef"
TRAFFIC = Path(__file__).parent / "fixtures" / "fortigate_traffic.cef"


def test_load_document_fortigate():
    doc = load_document(SHUTDOWN)
    assert doc.format == "cef"
    assert doc.vendor == "FortiGate"
    assert doc.vendor_block is not None
    assert doc.vendor_block["cef"]["name"] == "event:system"


def test_shutdown_extract_only_no_enrichable_iocs():
    report = build_report(SHUTDOWN, enrich=False)
    assert report.context.vendor == "FortiGate"
    assert report.context.log_format == "cef"
    assert report.context.event_name == "event:system"
    assert report.context.host_name == "FortiGate-80F"
    assert report.context.device_external_id == "FGT80FTK23038715"
    assert "unexpected power off" in (report.context.message or "")
    assert len(report.enrichable_artifacts) == 0

    hostnames = [
        a for a in report.artifacts if a.artifact.type == ArtifactType.HOSTNAME
    ]
    assert any(a.artifact.value == "FortiGate-80F" for a in hostnames)

    device_ids = [
        a for a in report.artifacts if a.artifact.type == ArtifactType.OTHER
    ]
    assert any(a.artifact.value == "FGT80FTK23038715" for a in device_ids)


def test_traffic_public_and_private_ips():
    report = build_report(TRAFFIC, enrich=False)
    ips = {
        a.artifact.normalized_value: a.artifact.scope
        for a in report.artifacts
        if a.artifact.type == ArtifactType.IP
    }
    assert "93.184.216.34" in ips
    assert ips["93.184.216.34"] == ArtifactScope.PUBLIC
    assert "192.168.1.10" in ips
    assert ips["192.168.1.10"] == ArtifactScope.INTERNAL
    assert len(report.enrichable_artifacts) >= 1


def test_json_wrapper_with_cef_message(tmp_path: Path):
    import json

    line = SHUTDOWN.read_text(encoding="utf-8").strip()
    wrapper = {"message": line}
    path = tmp_path / "wrapped.json"
    path.write_text(json.dumps(wrapper), encoding="utf-8")
    doc = load_document(path)
    assert doc.format == "cef"
    assert doc.vendor == "FortiGate"
