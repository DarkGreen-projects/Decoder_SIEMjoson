from pathlib import Path

from decoder_siem.parsers.email import parse_email_headers
from decoder_siem.parsers.normalize import looks_like_email_headers


def test_looks_like_email_headers():
    text = Path(__file__).parent / "fixtures" / "email_phishing_headers.txt"
    assert looks_like_email_headers(text.read_text(encoding="utf-8"))


def test_parse_phishing_headers():
    text = Path(__file__).parent / "fixtures" / "email_phishing_headers.txt"
    parsed = parse_email_headers(text.read_text(encoding="utf-8"))
    assert parsed.from_addr is not None
    assert parsed.from_addr.email == "ceo@legit-company.com"
    assert parsed.reply_to is not None
    assert parsed.reply_to.domain == "evil-phish.example"
    assert parsed.auth.spf == "fail"
    assert parsed.auth.dmarc == "fail"
    assert len(parsed.received_hops) >= 1
    assert parsed.received_hops[0].ip == "203.0.113.50"
