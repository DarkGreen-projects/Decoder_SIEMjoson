from pathlib import Path

from decoder_siem.analyzers.email_scorer import score_email
from decoder_siem.models import EmailVerdict
from decoder_siem.parsers.email import parse_email_headers


def _score_fixture(name: str):
    text = Path(__file__).parent / "fixtures" / name
    return score_email(parse_email_headers(text.read_text(encoding="utf-8")))


def test_score_phishing():
    result = _score_fixture("email_phishing_headers.txt")
    assert result.verdict == EmailVerdict.PHISHING
    assert result.criticality >= 55
    assert any("Reply-To" in ind or "DMARC" in ind for ind in result.indicators)


def test_score_spam():
    result = _score_fixture("email_spam_headers.txt")
    assert result.verdict == EmailVerdict.SPAM
    assert result.criticality >= 40


def test_score_clean():
    result = _score_fixture("email_clean_headers.txt")
    assert result.verdict == EmailVerdict.OTHER
    assert result.criticality < 40
    assert result.auth["spf"] == "pass"
    assert result.auth["dmarc"] == "pass"
