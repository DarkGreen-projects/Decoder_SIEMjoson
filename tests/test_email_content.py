from decoder_siem.analyzers.email_content import analyze_email_content
from decoder_siem.parsers.email import EmailLink, ParsedAttachment, ParsedEmail


def test_body_phishing_language():
    parsed = ParsedEmail(
        body_text="Please verify your account password immediately.",
        content_profile="headers_body",
    )
    signals = analyze_email_content(parsed)
    assert signals.score_delta >= 20
    assert any("phishing" in ind.lower() for ind in signals.indicators)


def test_link_mismatch():
    parsed = ParsedEmail(
        body_html='<a href="https://evil.com">https://bank.com/login</a>',
        body_links=[EmailLink(display_text="https://bank.com/login", href="https://evil.com")],
        content_profile="headers_body",
    )
    signals = analyze_email_content(parsed)
    assert signals.score_delta >= 25
    assert any("mismatch" in ind.lower() for ind in signals.indicators)


def test_risky_attachment():
    parsed = ParsedEmail(
        attachments=[
            ParsedAttachment(
                filename="invoice.pdf.exe",
                content_type="application/octet-stream",
                size_bytes=100,
                sha256="A" * 64,
            )
        ],
        content_profile="full_mime",
    )
    signals = analyze_email_content(parsed)
    assert signals.score_delta >= 30
    assert "invoice.pdf.exe" in signals.risky_attachments


def test_headers_only_no_content_signals():
    parsed = ParsedEmail(content_profile="headers_only")
    signals = analyze_email_content(parsed)
    assert signals.score_delta == 0
    assert not signals.indicators
