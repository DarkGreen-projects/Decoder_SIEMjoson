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
    assert result.verdict == EmailVerdict.SAFE
    assert result.criticality == 0
    assert result.confidence == "none"
    assert result.auth["spf"] == "pass"
    assert result.auth["dmarc"] == "pass"
    assert "SAFE" in result.summary
    assert result.detail is not None


def test_score_unclassifiable():
    result = _score_fixture("email_unclassifiable_headers.txt")
    assert result.verdict == EmailVerdict.UNCLASSIFIABLE
    assert any("From" in ind or "insufficienti" in ind.lower() for ind in result.indicators)


def test_confidence_scales_with_criticality():
    from decoder_siem.analyzers.email_scorer import confidence_from_criticality

    assert confidence_from_criticality(0) == "none"
    assert confidence_from_criticality(15) == "none"
    assert confidence_from_criticality(25) == "low"
    assert confidence_from_criticality(70) == "medium"
    assert confidence_from_criticality(95) == "high"
