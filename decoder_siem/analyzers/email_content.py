from __future__ import annotations

import re
from dataclasses import dataclass, field

from decoder_siem.parsers.email import EmailLink, ParsedAttachment, ParsedEmail, link_href_domain

PHISHING_BODY_PATTERNS = re.compile(
    r"\b("
    r"password|verify\s+your\s+account|urgent\s+action|wire\s+transfer|"
    r"mfa\s+reset|confirm\s+your\s+identity|account\s+suspended|"
    r"click\s+here\s+to\s+verify|security\s+alert|credential"
    r")\b",
    re.IGNORECASE,
)

SHORTENER_DOMAINS = {
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
}

RISKY_TLDS = {
    ".zip",
    ".mov",
    ".top",
    ".xyz",
    ".ru",
    ".cn",
    ".tk",
}

HIGH_RISK_EXTENSIONS = {
    ".exe",
    ".scr",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".bat",
    ".cmd",
    ".com",
    ".iso",
    ".lnk",
    ".hta",
    ".jar",
    ".msi",
    ".ps1",
    ".wsf",
}

MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz"}


@dataclass
class EmailContentSignals:
    score_delta: int = 0
    phishing_signals: int = 0
    spam_signals: int = 0
    indicators: list[str] = field(default_factory=list)
    suspicious_links: list[str] = field(default_factory=list)
    risky_attachments: list[str] = field(default_factory=list)


def _filename_lower(filename: str) -> str:
    return filename.lower().strip()


def _extension(filename: str) -> str:
    lower = _filename_lower(filename)
    dot = lower.rfind(".")
    if dot <= 0:
        return ""
    return lower[dot:]


def _has_double_extension(filename: str) -> bool:
    lower = _filename_lower(filename)
    parts = lower.split(".")
    return len(parts) >= 3 and parts[-1] in {
        "exe",
        "scr",
        "js",
        "vbs",
        "bat",
        "cmd",
        "com",
        "iso",
        "lnk",
        "hta",
        "jar",
    }


def _link_mismatch(link: EmailLink) -> bool:
    if not link.display_text or not link.href:
        return False
    display = link.display_text.strip().lower()
    if not display.startswith("http"):
        return False
    display_domain = link_href_domain(display)
    href_domain = link_href_domain(link.href)
    if not display_domain or not href_domain:
        return False
    return display_domain != href_domain


def _analyze_body(parsed: ParsedEmail, signals: EmailContentSignals) -> None:
    body_parts: list[str] = []
    if parsed.body_text:
        body_parts.append(parsed.body_text)
    if parsed.body_html and not parsed.body_text:
        body_parts.append(parsed.body_html)

    combined = "\n".join(body_parts).strip()
    if not combined and not parsed.body_links:
        return

    if combined and PHISHING_BODY_PATTERNS.search(combined):
        signals.score_delta += 20
        signals.phishing_signals += 1
        signals.indicators.append("Linguaggio phishing nel corpo")

    url_count = len(parsed.body_links)
    text_len = len(combined)
    if url_count >= 3 and text_len < 200:
        signals.score_delta += 15
        signals.phishing_signals += 1
        signals.indicators.append(f"Corpo breve con molti link ({url_count})")

    if not combined.strip() and url_count >= 1:
        signals.score_delta += 10
        signals.phishing_signals += 1
        signals.indicators.append("Corpo vuoto con link presenti")

    for link in parsed.body_links:
        href = link.href.strip()
        if not href.lower().startswith(("http://", "https://")):
            continue
        domain = link_href_domain(href)
        if domain and domain in SHORTENER_DOMAINS:
            signals.score_delta += 10
            signals.phishing_signals += 1
            signals.indicators.append(f"URL shortener nel corpo: {domain}")
            signals.suspicious_links.append(href)
        if re.match(r"https?://\d{1,3}(?:\.\d{1,3}){3}", href, re.I):
            signals.score_delta += 15
            signals.phishing_signals += 1
            signals.indicators.append(f"URL con IP letterale: {href[:80]}")
            signals.suspicious_links.append(href)
        if domain and any(domain.endswith(tld) for tld in RISKY_TLDS):
            signals.score_delta += 10
            signals.phishing_signals += 1
            signals.indicators.append(f"TLD sospetto nel link: {domain}")
            signals.suspicious_links.append(href)
        if _link_mismatch(link):
            signals.score_delta += 25
            signals.phishing_signals += 1
            signals.indicators.append(
                f"Link mismatch: testo '{link.display_text[:40]}' → {href[:60]}"
            )
            signals.suspicious_links.append(href)


def _analyze_attachments(parsed: ParsedEmail, signals: EmailContentSignals) -> None:
    if not parsed.attachments:
        return

    has_body = bool(parsed.body_text and parsed.body_text.strip())
    if not has_body:
        signals.score_delta += 15
        signals.phishing_signals += 1
        signals.indicators.append(
            f"Allegati ({len(parsed.attachments)}) senza corpo testuale"
        )

    for att in parsed.attachments:
        ext = _extension(att.filename)
        name = att.filename
        if ext in HIGH_RISK_EXTENSIONS or _has_double_extension(name):
            signals.score_delta += 30
            signals.phishing_signals += 1
            signals.indicators.append(f"Allegato ad alto rischio: {name}")
            signals.risky_attachments.append(name)
        elif ext in MACRO_EXTENSIONS:
            signals.score_delta += 20
            signals.phishing_signals += 1
            signals.indicators.append(f"Allegato Office con macro probabile: {name}")
            signals.risky_attachments.append(name)
        elif ext in ARCHIVE_EXTENSIONS:
            signals.score_delta += 8
            signals.spam_signals += 1
            signals.indicators.append(f"Archivio compresso allegato: {name}")


def analyze_email_content(parsed: ParsedEmail) -> EmailContentSignals:
    signals = EmailContentSignals()
    if parsed.content_profile == "headers_only":
        return signals

    _analyze_body(parsed, signals)
    _analyze_attachments(parsed, signals)
    signals.score_delta = min(50, signals.score_delta)
    return signals
