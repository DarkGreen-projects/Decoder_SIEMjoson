from __future__ import annotations

import re

from decoder_siem.models import EmailAnalysisResult, EmailVerdict
from decoder_siem.parsers.email import ParsedEmail, ParsedAddress

FREE_MAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
    "aol.com",
    "mail.com",
    "gmx.com",
    "yandex.com",
}

PHISHING_SUBJECT_PATTERNS = re.compile(
    r"\b(password|invoice|urgent|verify|account|suspend|credential|payment|security\s+alert)\b",
    re.IGNORECASE,
)

EXEC_DISPLAY_HINTS = re.compile(
    r"\b(ceo|cfo|director|president|manager|hr|payroll|finance)\b",
    re.IGNORECASE,
)


def _domain(addr: ParsedAddress | None) -> str | None:
    if not addr or not addr.domain:
        return None
    return addr.domain.lower()


def _auth_is_fail(value: str) -> bool:
    return value.lower() in ("fail", "softfail", "permerror", "temperror")


def _auth_is_weak(value: str) -> bool:
    return value.lower() in ("fail", "softfail", "none", "neutral", "permerror", "temperror")


def confidence_from_criticality(criticality: int) -> str:
    """Confidenza allineata al punteggio di rischio (non al verdetto)."""
    if criticality >= 90:
        return "high"
    if criticality >= 60:
        return "medium"
    if criticality >= 20:
        return "low"
    return "none"


CONFIDENCE_LABEL_IT = {
    "none": "nullo",
    "low": "bassa",
    "medium": "media",
    "high": "alta",
}


def score_email(parsed: ParsedEmail) -> EmailAnalysisResult:
    score = 0
    indicators: list[str] = []
    phishing_signals = 0
    spam_signals = 0

    auth = {
        "spf": parsed.auth.spf,
        "dkim": parsed.auth.dkim,
        "dmarc": parsed.auth.dmarc,
    }

    if _auth_is_fail(parsed.auth.dmarc):
        score += 30
        phishing_signals += 1
        indicators.append("DMARC fail")
    if _auth_is_fail(parsed.auth.spf):
        score += 25
        phishing_signals += 1
        indicators.append("SPF fail")
    if parsed.auth.dkim in ("fail", "none") or _auth_is_fail(parsed.auth.dkim):
        score += 15
        if parsed.auth.dkim == "none":
            indicators.append("DKIM assente")
        else:
            indicators.append(f"DKIM {parsed.auth.dkim}")

    from_domain = _domain(parsed.from_addr)
    reply_domain = _domain(parsed.reply_to)
    return_domain = _domain(parsed.return_path)

    if from_domain and reply_domain and from_domain != reply_domain:
        score += 20
        phishing_signals += 1
        indicators.append(f"From ({from_domain}) ≠ Reply-To ({reply_domain})")

    if from_domain and return_domain and from_domain != return_domain:
        score += 15
        phishing_signals += 1
        indicators.append(f"Return-Path ({return_domain}) ≠ From ({from_domain})")

    if parsed.from_addr and parsed.from_addr.display_name:
        display = parsed.from_addr.display_name
        if EXEC_DISPLAY_HINTS.search(display) and from_domain in FREE_MAIL_DOMAINS:
            score += 15
            phishing_signals += 1
            indicators.append("Display name esecutivo con dominio free-mail")

    if parsed.subject and PHISHING_SUBJECT_PATTERNS.search(parsed.subject):
        score += 10
        phishing_signals += 1
        indicators.append(f"Subject sospetto: {parsed.subject[:80]}")

    if parsed.precedence and parsed.precedence.lower() == "bulk":
        score += 15
        spam_signals += 1
        indicators.append("Precedence: bulk")

    if parsed.list_unsubscribe:
        score += 10
        spam_signals += 1
        indicators.append("List-Unsubscribe presente")

    if parsed.list_unsubscribe or (parsed.precedence and parsed.precedence.lower() == "bulk"):
        if _auth_is_weak(parsed.auth.spf) or _auth_is_weak(parsed.auth.dkim):
            score += 10
            spam_signals += 1
            indicators.append("Mail bulk con autenticazione debole")

    hop_count = len(parsed.received_hops)
    if hop_count > 8:
        score += 10
        spam_signals += 1
        indicators.append(f"Catena Received lunga ({hop_count} hop)")

    if not parsed.message_id or "@" not in (parsed.message_id or ""):
        score += 10
        spam_signals += 1
        indicators.append("Message-ID assente o malformato")

    if from_domain in FREE_MAIL_DOMAINS and parsed.subject:
        if re.search(r"\b(invoice|order|contract|proposal)\b", parsed.subject, re.I):
            score += 10
            spam_signals += 1
            indicators.append("Mittente free-mail con subject business-like")

    if (
        parsed.auth.spf == "pass"
        and parsed.auth.dkim == "pass"
        and parsed.auth.dmarc == "pass"
        and from_domain
        and (not reply_domain or reply_domain == from_domain)
        and (not return_domain or return_domain == from_domain)
    ):
        score = max(0, score - 25)
        indicators.append("SPF/DKIM/DMARC pass e identità allineate")

    criticality = min(100, score)

    verdict = EmailVerdict.OTHER

    identity_mismatch = bool(
        (from_domain and reply_domain and from_domain != reply_domain)
        or (from_domain and return_domain and from_domain != return_domain)
    )
    strong_phishing = phishing_signals >= 1 and (
        _auth_is_fail(parsed.auth.dmarc) or identity_mismatch
    )

    if criticality >= 55 and strong_phishing:
        verdict = EmailVerdict.PHISHING
    elif criticality >= 40 and spam_signals >= 1 and not strong_phishing:
        verdict = EmailVerdict.SPAM
    elif criticality >= 40 and spam_signals > phishing_signals and not strong_phishing:
        verdict = EmailVerdict.SPAM
    else:
        verdict = EmailVerdict.OTHER

    confidence = confidence_from_criticality(criticality)
    confidence_it = CONFIDENCE_LABEL_IT[confidence]

    verdict_label = {
        EmailVerdict.PHISHING: "PHISHING",
        EmailVerdict.SPAM: "SPAM",
        EmailVerdict.OTHER: "ALTRO",
    }[verdict]

    summary = (
        f"Verdetto email: {verdict_label} — criticità {criticality}/100 "
        f"(confidenza {confidence_it})"
    )

    return EmailAnalysisResult(
        verdict=verdict,
        criticality=criticality,
        confidence=confidence,
        indicators=indicators,
        auth=auth,
        summary=summary,
    )
