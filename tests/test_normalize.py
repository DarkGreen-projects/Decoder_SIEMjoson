import json

import pytest

from decoder_siem.parsers.loader import load_text
from decoder_siem.parsers.normalize import normalize_pasted_text, parse_json_lenient

DEFENDER_SNIPPET = '{"MicrosoftGraph": {"id": "test-123", "title": "LDAP recon"}}'


def test_normalize_nbsp():
    text = '{"Cynet":\u00a0{"HostIp":\u00a0"10.0.0.1"}}'
    norm = normalize_pasted_text(text)
    assert "\u00a0" not in norm
    assert parse_json_lenient(norm)["Cynet"]["HostIp"] == "10.0.0.1"


def test_parse_json_with_prefix_text():
    raw = "Alert from SIEM:\n" + DEFENDER_SNIPPET + "\nend"
    doc = load_text(raw)
    assert doc.vendor == "MicrosoftDefender"


def test_parse_json_wrapped_in_outer_quotes():
    wrapped = json.dumps(DEFENDER_SNIPPET)
    doc = load_text(wrapped)
    assert doc.vendor == "MicrosoftDefender"


def test_parse_json_doubled_quotes():
    broken = DEFENDER_SNIPPET.replace('"', '""')
    doc = load_text(broken)
    assert doc.vendor == "MicrosoftDefender"


def test_invalid_raises_helpful():
    with pytest.raises(ValueError, match="JSON valido"):
        parse_json_lenient("not json at all")
