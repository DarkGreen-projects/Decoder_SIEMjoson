from pathlib import Path

import pytest

from decoder_siem.extractors import GenericExtractor, merge_artifacts
from decoder_siem.extractors.cynet import CynetExtractor
from decoder_siem.models import ArtifactScope, ArtifactType
from decoder_siem.parser import prepare_incident_data
from decoder_siem.pipeline import build_report, extract_artifacts_from_file

FIXTURE = Path(__file__).parent / "fixtures" / "cynet_malicious_pdf.json"

INFECTED_SHA = "553C792B1B8F98D7BCD59267B4D5FF7755CBCE019597DD8EBAD4AFE1A00CAC8D"
PROCESS_SHA = "B1EF03497D6823CE6D8BC77D6EF8BDC4A21FF560AD7A613D539C9851BECF2405"
GRANDPARENT_SHA = "23C281B8D463DDA454D05118DB7B860013E7666D38BB8BED9E5430E6216F7B2B"
HOST_IP = "192.168.2.66"


@pytest.fixture
def cynet_block():
    _, vendor, block = prepare_incident_data(FIXTURE)
    assert vendor == "Cynet"
    return block


def test_parse_nested_incident_json(cynet_block):
    nested = cynet_block["IncidentJsonDescription"]
    assert isinstance(nested, dict)
    assert nested["Host Ip"] == HOST_IP
    assert "Extra Info" in nested


def test_cynet_extractor_hashes_and_ip(cynet_block):
    artifacts = CynetExtractor().extract(cynet_block)
    hashes = {
        a.normalized_value
        for a in artifacts
        if a.type == ArtifactType.HASH_SHA256
    }
    assert INFECTED_SHA in hashes
    assert PROCESS_SHA in hashes
    assert GRANDPARENT_SHA in hashes

    ips = [a for a in artifacts if a.type == ArtifactType.IP]
    assert any(a.normalized_value == HOST_IP for a in ips)


def test_internal_ip_scope(cynet_block):
    artifacts = merge_artifacts(CynetExtractor().extract(cynet_block))
    host_ips = [
        a for a in artifacts
        if a.type == ArtifactType.IP and a.normalized_value == HOST_IP
    ]
    assert host_ips
    assert all(a.scope == ArtifactScope.INTERNAL for a in host_ips)


def test_file_paths_extracted(cynet_block):
    artifacts = CynetExtractor().extract(cynet_block)
    paths = {a.value for a in artifacts if a.type == ArtifactType.FILE_PATH}
    assert "/Volumes/Public/sample.pdf" in paths
    assert "/Applications/Adobe Illustrator" in paths


def test_full_pipeline_no_enrich():
    report = build_report(FIXTURE, enrich=False)
    assert report.context.vendor == "Cynet"
    assert report.context.host_ip == HOST_IP
    assert report.context.malware_id == "TR/VBS.Malware"
    assert len(report.artifacts) >= 3
    assert len(report.internal_ips) >= 1


def test_generic_regex_on_description(cynet_block):
    text = cynet_block["IncidentDescription"]
    found = GenericExtractor().extract(text, "test")
    sha_values = {
        a.normalized_value for a in found if a.type == ArtifactType.HASH_SHA256
    }
    assert INFECTED_SHA in sha_values
    assert PROCESS_SHA in sha_values


def test_extract_artifacts_from_file():
    artifacts, ctx = extract_artifacts_from_file(FIXTURE)
    assert ctx.vendor == "Cynet"
    assert len(artifacts) > 0


def test_deduplicate_provenance(cynet_block):
    artifacts = merge_artifacts(
        CynetExtractor().extract(cynet_block),
        GenericExtractor().extract(cynet_block, "Cynet"),
    )
    infected = [
        a for a in artifacts
        if a.normalized_value == INFECTED_SHA
    ]
    assert len(infected) == 1
    assert len(infected[0].provenance) >= 2
