from pathlib import Path

from decoder_siem.alert_guidance import alert_guidance_to_markdown, build_alert_guidance
from decoder_siem.pipeline import build_report_from_text

DEFENDER = Path(__file__).parent / "fixtures" / "defender_ldap_recon.json"
FORTIGATE = Path(__file__).parent / "fixtures" / "fortigate_shutdown.cef"
CYNET = Path(__file__).parent / "fixtures" / "cynet_malicious_pdf.json"


def test_defender_ldap_guidance():
    report = build_report_from_text(DEFENDER.read_text(encoding="utf-8"), enrich=False)
    label, desc, focus, key_facts, actions = build_alert_guidance(
        report.context, report
    )
    assert "LDAP" in label or "Ricognizione" in label
    assert "172.27.38.26" in desc or any("172.27.38.26" in f for f in focus)
    assert any("NPOTRN2DC11" in k or "npotrn2dc11" in k.lower() for k in key_facts + focus)
    assert any("Schema" in k or "Enterprise" in k for k in key_facts)
    assert len(actions) >= 2

    md = alert_guidance_to_markdown(report.context, report)
    assert "Guida all'alert" in md
    assert "Elementi chiave estratti" in md
    assert "Azioni suggerite" in md
    assert "172.27.38.26" in md


def test_fortigate_system_guidance():
    report = build_report_from_text(FORTIGATE.read_text(encoding="utf-8"), enrich=False)
    label, desc, focus, key_facts, _ = build_alert_guidance(report.context, report)
    assert "sistema" in label.lower() or "system" in label.lower()
    assert "FortiGate-80F" in desc or any("FortiGate" in k for k in key_facts)
    assert any("FGT80" in k for k in key_facts) or "FGT80" in desc
    assert any("shutdown" in d.lower() or "power" in d.lower() for d in [desc] + focus)


def test_cynet_malware_guidance():
    report = build_report_from_text(CYNET.read_text(encoding="utf-8"), enrich=False)
    label, desc, _, key_facts, _ = build_alert_guidance(report.context, report)
    assert "Cynet" in label
    assert "malevolo" in label.lower() or "File" in label or "infetto" in label.lower()
    md = alert_guidance_to_markdown(report.context, report)
    assert "192.168" in md or "Mac mini" in md or any("192.168" in k for k in key_facts)
    assert "TR/VBS" in md or "Malware" in md or "trojan" in desc.lower()
