from pathlib import Path

from decoder_siem.parsers.email import (
    extract_links_from_html,
    parse_email_message,
    parse_email_headers,
)
from decoder_siem.parsers.loader import load_text

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_eml_with_html_body():
    text = (FIXTURES / "email_with_body_phishing.eml").read_text(encoding="utf-8")
    parsed = parse_email_message(text)
    assert parsed.content_profile in ("headers_body", "full_mime")
    assert parsed.body_text
    assert parsed.body_html
    assert parsed.body_links
    assert any("evil-phish" in link.href for link in parsed.body_links)


def test_parse_eml_with_attachment():
    text = (FIXTURES / "email_with_attachment.eml").read_text(encoding="utf-8")
    parsed = parse_email_message(text)
    assert parsed.content_profile == "full_mime"
    assert len(parsed.attachments) == 1
    assert parsed.attachments[0].filename == "invoice.pdf.exe"
    assert len(parsed.attachments[0].sha256) == 64


def test_parse_headers_with_body_text():
    text = (FIXTURES / "email_headers_with_body.txt").read_text(encoding="utf-8")
    parsed = parse_email_headers(text)
    assert parsed.content_profile == "headers_body"
    assert parsed.body_text
    assert "meeting" in parsed.body_text.lower()


def test_load_text_eml_uses_full_parser():
    text = (FIXTURES / "email_with_attachment.eml").read_text(encoding="utf-8")
    doc = load_text(text, source_hint="sample.eml")
    assert doc.format == "email"
    assert doc.data["content_profile"] == "full_mime"
    assert len(doc.data["attachments"]) == 1


def test_extract_links_from_html():
    links = extract_links_from_html(
        '<a href="https://evil.example">Click here</a>'
    )
    assert len(links) == 1
    assert links[0].href == "https://evil.example"
