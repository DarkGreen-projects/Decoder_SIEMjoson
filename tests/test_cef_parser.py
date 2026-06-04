from pathlib import Path

import pytest

from decoder_siem.parsers.cef import parse_cef_extension, parse_cef_line

SHUTDOWN = Path(__file__).parent / "fixtures" / "fortigate_shutdown.cef"


def test_parse_extension_with_spaces():
    ext = "FTNTFGTlogdesc=Device shutdown msg=Fortigate had experienced an unexpected power off!"
    parsed = parse_cef_extension(ext)
    assert parsed["FTNTFGTlogdesc"] == "Device shutdown"
    assert "unexpected power off" in parsed["msg"]


def test_parse_fortigate_shutdown_line():
    line = SHUTDOWN.read_text(encoding="utf-8").strip()
    result = parse_cef_line(line)

    assert result["format"] == "cef"
    assert result["syslog"]["hostname"] == "FortiGate-80F"
    assert result["syslog"]["priority"] == 186

    cef = result["cef"]
    assert cef["vendor"] == "Fortinet"
    assert cef["product"] == "Fortigate"
    assert cef["name"] == "event:system"
    assert cef["severity"] == 6

    ext = cef["extension"]
    assert ext["deviceExternalId"] == "FGT80FTK23038715"
    assert ext["FTNTFGTlogdesc"] == "Device shutdown"
    assert "unexpected power off" in ext["msg"]
    assert ext["FTNTFGTlevel"] == "critical"


def test_parse_invalid_line():
    with pytest.raises(ValueError):
        parse_cef_line("not a cef log")
