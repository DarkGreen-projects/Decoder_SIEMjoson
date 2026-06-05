from pathlib import Path

from decoder_siem.models import EmailVerdict
from decoder_siem.pipeline import build_report_from_text
from decoder_siem.table_export import email_verdict_html


def test_pipeline_phishing_headers():
    text = Path(__file__).parent / "fixtures" / "email_phishing_headers.txt"
    report = build_report_from_text(text.read_text(encoding="utf-8"), enrich=False)
    assert report.context.vendor == "EmailHeaders"
    analysis = report.context.extra.get("email_analysis")
    assert analysis is not None
    assert analysis["verdict"] == EmailVerdict.PHISHING.value
    assert report.context.mail_from is not None
    ips = [a for a in report.artifacts if a.artifact.type.value == "ip"]
    assert any(a.artifact.normalized_value == "203.0.113.50" for a in ips)
    html_out = email_verdict_html(report)
    assert "PHISHING" in html_out


def test_pipeline_clean_headers():
    text = Path(__file__).parent / "fixtures" / "email_clean_headers.txt"
    report = build_report_from_text(text.read_text(encoding="utf-8"), enrich=False)
    analysis = report.context.extra.get("email_analysis")
    assert analysis["verdict"] == EmailVerdict.OTHER.value
