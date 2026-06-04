from pathlib import Path

from decoder_siem.extractors.cynet import CynetExtractor
from decoder_siem.models import ArtifactType
from decoder_siem.parser import prepare_incident_data

FIXTURE = Path(__file__).parent / "fixtures" / "cynet_malicious_pdf.json"


def test_extract_context_malware():
    _, _, block = prepare_incident_data(FIXTURE)
    ctx = CynetExtractor().extract_context(block)
    assert ctx["malware_id"] == "TR/VBS.Malware"
    assert ctx["malware_type"] == "trojan"
    assert ctx["incident_name"] is not None
    assert "Malicious Binary" in ctx["incident_name"]


def test_malware_label_artifact():
    _, _, block = prepare_incident_data(FIXTURE)
    artifacts = CynetExtractor().extract(block)
    labels = [a for a in artifacts if a.type == ArtifactType.MALWARE_LABEL]
    values = {a.value for a in labels}
    assert "TR/VBS.Malware" in values
    assert "trojan" in values
