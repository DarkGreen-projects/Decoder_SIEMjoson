from pathlib import Path

from decoder_siem.analyzers.email_scorer import score_email
from decoder_siem.models import EmailVerdict
from decoder_siem.parsers.email import parse_email_message

FIXTURES = Path(__file__).parent / "fixtures"


def test_score_eml_with_body_phishing():
    text = (FIXTURES / "email_with_body_phishing.eml").read_text(encoding="utf-8")
    result = score_email(parse_email_message(text))
    assert result.verdict == EmailVerdict.PHISHING
    assert result.body_analyzed is True
    assert result.content_profile in ("headers_body", "full_mime")
    assert result.content_indicators
    assert "header" in (result.detail or "").lower()


def test_score_eml_with_risky_attachment():
    text = (FIXTURES / "email_with_attachment.eml").read_text(encoding="utf-8")
    result = score_email(parse_email_message(text))
    assert result.attachments_count == 1
    assert any("allegato" in ind.lower() for ind in result.content_indicators)
