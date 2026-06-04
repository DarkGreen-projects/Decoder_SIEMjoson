from pathlib import Path

from decoder_siem.alert_guidance import alert_guidance_to_markdown, build_alert_guidance
from decoder_siem.pipeline import build_report_from_text

DEFENDER = Path(__file__).parent / "fixtures" / "defender_ldap_recon.json"
FORTIGATE = Path(__file__).parent / "fixtures" / "fortigate_shutdown.cef"
CYNET = Path(__file__).parent / "fixtures" / "cynet_malicious_pdf.json"


def test_defender_ldap_guidance():
    report = build_report_from_text(DEFENDER.read_text(encoding="utf-8"), enrich=False)
    label, desc, focus = build_alert_guidance(report.context, report)
    assert "LDAP" in label or "Ricognizione" in label
    assert "Discovery" in desc or "ricognizione" in desc.lower()
    assert len(focus) >= 3

    md = alert_guidance_to_markdown(report.context, report)
    assert "Guida all'alert" in md
    assert "Dove portare l'attenzione" in md


def test_fortigate_system_guidance():
    report = build_report_from_text(FORTIGATE.read_text(encoding="utf-8"), enrich=False)
    label, _, focus = build_alert_guidance(report.context, report)
    assert "sistema" in label.lower() or "system" in label.lower()
    assert any("manutenzione" in f.lower() or "power" in f.lower() or "firewall" in f.lower() for f in focus)


def test_cynet_malware_guidance():
    report = build_report_from_text(CYNET.read_text(encoding="utf-8"), enrich=False)
    label, _, _ = build_alert_guidance(report.context, report)
    assert "Cynet" in label
    assert "malevolo" in label.lower() or "File" in label or "binario" in label.lower()
