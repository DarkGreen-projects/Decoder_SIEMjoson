from pathlib import Path

import pytest

from decoder_siem.parsers.loader import load_text
from decoder_siem.pipeline import build_report_from_text
from decoder_siem.table_export import TABLE_HEADERS, report_to_rows

CYNET = Path(__file__).parent / "fixtures" / "cynet_malicious_pdf.json"
FORTIGATE = Path(__file__).parent / "fixtures" / "fortigate_shutdown.cef"
DEFENDER = Path(__file__).parent / "fixtures" / "defender_ldap_recon.json"


def test_load_text_cynet():
    doc = load_text(CYNET.read_text(encoding="utf-8"))
    assert doc.vendor == "Cynet"
    assert doc.format == "json"


def test_load_text_fortigate():
    doc = load_text(FORTIGATE.read_text(encoding="utf-8"))
    assert doc.vendor == "FortiGate"
    assert doc.format == "cef"


def test_load_text_defender():
    doc = load_text(DEFENDER.read_text(encoding="utf-8"))
    assert doc.vendor == "MicrosoftDefender"


def test_load_text_empty():
    with pytest.raises(ValueError, match="vuoto"):
        load_text("   ")


def test_build_report_from_text():
    text = CYNET.read_text(encoding="utf-8")
    report = build_report_from_text(text, enrich=False)
    assert report.source_file == "(input)"
    rows = report_to_rows(report)
    assert len(rows) >= 3
    assert len(rows[0]) == len(TABLE_HEADERS)


def test_report_to_rows_columns():
    report = build_report_from_text(
        FORTIGATE.read_text(encoding="utf-8"),
        enrich=False,
    )
    rows = report_to_rows(report)
    assert rows
    assert rows[0][0] in ("hostname", "ip", "other", "hash_sha256", "domain", "url")


def test_gui_module_import():
    import decoder_siem.gui  # noqa: F401
