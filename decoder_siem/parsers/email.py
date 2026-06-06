from __future__ import annotations

import hashlib
import html
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlparse

from decoder_siem.input_guard import (
    max_email_attachment_bytes,
    max_email_attachments,
    max_string_scan_len,
)

IPV4_IN_TEXT = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
AUTH_RESULT_RE = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|permerror|temperror)",
    re.IGNORECASE,
)
RECEIVED_BY_RE = re.compile(
    r"from\s+([^\s;(]+)",
    re.IGNORECASE,
)
RECEIVED_IP_RE = re.compile(
    r"\[([0-9a-fA-F:.]+)\]",
)
_HREF_RE = re.compile(
    r"""href\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_TAG_RE = re.compile(r"<[^>]+>")


@dataclass
class ParsedAddress:
    raw: str
    display_name: str
    email: str
    domain: str | None = None

    def __post_init__(self) -> None:
        if self.email and "@" in self.email:
            self.domain = self.email.rsplit("@", 1)[-1].lower().strip(">")


@dataclass
class ReceivedHop:
    raw: str
    by_host: str | None = None
    from_host: str | None = None
    ip: str | None = None
    date: str | None = None


@dataclass
class AuthResults:
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"


@dataclass
class ParsedAttachment:
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    is_inline: bool = False


@dataclass
class EmailLink:
    display_text: str
    href: str


@dataclass
class ParsedEmail:
    headers: dict[str, list[str]] = field(default_factory=dict)
    received_hops: list[ReceivedHop] = field(default_factory=list)
    auth: AuthResults = field(default_factory=AuthResults)
    from_addr: ParsedAddress | None = None
    reply_to: ParsedAddress | None = None
    return_path: ParsedAddress | None = None
    sender: ParsedAddress | None = None
    to_addrs: list[str] = field(default_factory=list)
    subject: str | None = None
    message_id: str | None = None
    date: str | None = None
    body_text: str | None = None
    body_html: str | None = None
    attachments: list[ParsedAttachment] = field(default_factory=list)
    body_links: list[EmailLink] = field(default_factory=list)
    content_profile: str = "headers_only"
    precedence: str | None = None
    list_unsubscribe: bool = False


class _LinkHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[EmailLink] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        href = None
        for key, value in attrs:
            if key.lower() == "href" and value:
                href = value.strip()
                break
        if href:
            self._current_href = href
            self._current_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a" or not self._current_href:
            return
        display = " ".join(self._current_text).strip()
        self.links.append(EmailLink(display_text=display, href=self._current_href))
        self._current_href = None
        self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)


def _truncate_body(text: str | None) -> str | None:
    if not text:
        return None
    limit = max_string_scan_len()
    if len(text) > limit:
        return text[:limit]
    return text


def _html_to_text(raw_html: str) -> str:
    text = _TAG_RE.sub(" ", raw_html)
    return html.unescape(re.sub(r"\s+", " ", text)).strip()


def extract_links_from_html(raw_html: str) -> list[EmailLink]:
    parser = _LinkHTMLParser()
    try:
        parser.feed(raw_html)
        parser.close()
    except Exception:  # noqa: BLE001
        for match in _HREF_RE.finditer(raw_html):
            parser.links.append(EmailLink(display_text="", href=match.group(1).strip()))
    seen: set[tuple[str, str]] = set()
    unique: list[EmailLink] = []
    for link in parser.links:
        key = (link.display_text, link.href)
        if key not in seen and link.href:
            seen.add(key)
            unique.append(link)
    return unique


def _parse_address(raw: str | None) -> ParsedAddress | None:
    if not raw or not raw.strip():
        return None
    display, email = parseaddr(raw.strip())
    email = email.strip().lower()
    if not email:
        return ParsedAddress(raw=raw.strip(), display_name=display.strip(), email="", domain=None)
    return ParsedAddress(
        raw=raw.strip(),
        display_name=display.strip(),
        email=email,
    )


def _collect_headers(msg: Any) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = {}
    if hasattr(msg, "items"):
        for key, value in msg.items():
            headers.setdefault(key.lower(), []).append(str(value).strip())
    return headers


def _parse_received_hop(line: str) -> ReceivedHop:
    hop = ReceivedHop(raw=line)
    by_match = re.search(r"\bby\s+([^\s;(]+)", line, re.IGNORECASE)
    if by_match:
        hop.by_host = by_match.group(1).strip()
    from_match = RECEIVED_BY_RE.search(line)
    if from_match:
        hop.from_host = from_match.group(1).strip()
    ip_match = RECEIVED_IP_RE.search(line)
    if ip_match:
        hop.ip = ip_match.group(1)
    else:
        ips = IPV4_IN_TEXT.findall(line)
        if ips:
            hop.ip = ips[-1]
    date_match = re.search(r";\s*(.+)$", line)
    if date_match:
        hop.date = date_match.group(1).strip()
    return hop


def _merge_auth_results(target: AuthResults, text: str) -> None:
    for match in AUTH_RESULT_RE.finditer(text):
        kind = match.group(1).lower()
        value = match.group(2).lower()
        current = getattr(target, kind)
        priority = {
            "none": 0,
            "pass": 1,
            "neutral": 2,
            "softfail": 3,
            "temperror": 4,
            "permerror": 4,
            "fail": 5,
        }
        if priority.get(value, 0) > priority.get(current, 0):
            setattr(target, kind, value)


def _extract_auth(headers: dict[str, list[str]]) -> AuthResults:
    auth = AuthResults()
    for key in ("authentication-results", "arc-authentication-results"):
        for value in headers.get(key, []):
            _merge_auth_results(auth, value)
    for value in headers.get("received-spf", []):
        match = re.search(
            r"\b(pass|fail|softfail|neutral|none|permerror|temperror)\b",
            value,
            re.IGNORECASE,
        )
        if match:
            _merge_auth_results(auth, f"spf={match.group(1).lower()}")
    if not headers.get("dkim-signature") and auth.dkim == "none":
        auth.dkim = "none"
    elif headers.get("dkim-signature") and auth.dkim == "none":
        auth.dkim = "present"
    return auth


def _part_payload_bytes(part: Any) -> bytes | None:
    try:
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            return payload
        if isinstance(payload, str):
            return payload.encode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return None
    return None


def _extract_body_parts(msg: Any) -> tuple[str | None, str | None]:
    if msg is None:
        return None, None
    plain_parts: list[str] = []
    html_parts: list[str] = []
    try:
        if msg.is_multipart():
            for part in msg.walk():
                disposition = (part.get_content_disposition() or "").lower()
                if disposition == "attachment":
                    continue
                ctype = part.get_content_type()
                if ctype.startswith("multipart/"):
                    continue
                try:
                    payload = part.get_content()
                except Exception:  # noqa: BLE001
                    continue
                if not isinstance(payload, str) or not payload.strip():
                    continue
                if ctype == "text/plain":
                    plain_parts.append(payload)
                elif ctype == "text/html":
                    html_parts.append(payload)
        else:
            ctype = msg.get_content_type()
            payload = msg.get_content()
            if isinstance(payload, str) and payload.strip():
                if ctype == "text/html":
                    html_parts.append(payload)
                else:
                    plain_parts.append(payload)
    except Exception:  # noqa: BLE001
        return None, None

    plain = "\n".join(plain_parts).strip() if plain_parts else None
    html_body = "\n".join(html_parts).strip() if html_parts else None
    if not plain and html_body:
        plain = _html_to_text(html_body)
    return _truncate_body(plain), _truncate_body(html_body)


def _extract_attachments(msg: Any) -> list[ParsedAttachment]:
    if msg is None or not hasattr(msg, "walk"):
        return []
    attachments: list[ParsedAttachment] = []
    max_count = max_email_attachments()
    max_bytes = max_email_attachment_bytes()
    try:
        for part in msg.walk():
            if len(attachments) >= max_count:
                break
            disposition = (part.get_content_disposition() or "").lower()
            filename = part.get_filename()
            content_type = part.get_content_type()
            is_inline = disposition == "inline"
            is_attachment = disposition == "attachment" or bool(filename)
            if not is_attachment:
                continue
            raw = _part_payload_bytes(part)
            if raw is None:
                continue
            if len(raw) > max_bytes:
                continue
            name = filename or f"unnamed-{len(attachments) + 1}"
            attachments.append(
                ParsedAttachment(
                    filename=name,
                    content_type=content_type,
                    size_bytes=len(raw),
                    sha256=hashlib.sha256(raw).hexdigest().upper(),
                    is_inline=is_inline,
                )
            )
    except Exception:  # noqa: BLE001
        return attachments
    return attachments


def _detect_content_profile(parsed: ParsedEmail) -> str:
    has_body = bool(parsed.body_text and parsed.body_text.strip())
    has_html = bool(parsed.body_html and parsed.body_html.strip())
    has_attachments = bool(parsed.attachments)
    if has_attachments or (has_body and has_html):
        return "full_mime"
    if has_body or has_html:
        return "headers_body"
    return "headers_only"


def _populate_from_message(parsed: ParsedEmail, msg: Any) -> ParsedEmail:
    headers = _collect_headers(msg)
    parsed.headers = headers
    parsed.received_hops = [
        _parse_received_hop(line) for line in headers.get("received", [])
    ]
    parsed.auth = _extract_auth(headers)
    parsed.from_addr = _parse_address(_first(headers, "from"))
    parsed.reply_to = _parse_address(_first(headers, "reply-to"))
    parsed.return_path = _parse_address(_first(headers, "return-path"))
    parsed.sender = _parse_address(_first(headers, "sender"))
    parsed.to_addrs = headers.get("to", [])
    parsed.subject = _first(headers, "subject")
    parsed.message_id = _first(headers, "message-id")
    parsed.date = _first(headers, "date")
    parsed.precedence = _first(headers, "precedence")
    parsed.list_unsubscribe = bool(headers.get("list-unsubscribe"))
    parsed.body_text, parsed.body_html = _extract_body_parts(msg)
    parsed.attachments = _extract_attachments(msg)
    if parsed.body_html:
        parsed.body_links = extract_links_from_html(parsed.body_html)
    parsed.content_profile = _detect_content_profile(parsed)
    return parsed


def _first(headers: dict[str, list[str]], key: str) -> str | None:
    values = headers.get(key)
    if values:
        return values[0]
    return None


def looks_like_mime_message(text: str) -> bool:
    lower = text.lower()
    if "content-type: multipart/" in lower:
        return True
    if "boundary=" in lower and "mime-version:" in lower:
        return True
    if re.search(r"----=_", text):
        return True
    if "content-transfer-encoding: base64" in lower:
        return True
    return False


def parse_email_headers(text: str) -> ParsedEmail:
    """Parse RFC 5322 headers from pasted text or header block."""
    parser = Parser(policy=policy.default)
    msg = parser.parsestr(text)
    return _populate_from_message(ParsedEmail(), msg)


def parse_email_message(text: str) -> ParsedEmail:
    """Parse full .eml content (headers + optional body)."""
    content = text.encode("utf-8", errors="replace")
    msg = BytesParser(policy=policy.default).parsebytes(content)
    return _populate_from_message(ParsedEmail(), msg)


def parsed_email_to_dict(parsed: ParsedEmail) -> dict[str, Any]:
    """Serialize ParsedEmail for LoadedDocument.vendor_block."""
    return {
        "headers": parsed.headers,
        "received_hops": [
            {
                "raw": h.raw,
                "by_host": h.by_host,
                "from_host": h.from_host,
                "ip": h.ip,
                "date": h.date,
            }
            for h in parsed.received_hops
        ],
        "auth": {
            "spf": parsed.auth.spf,
            "dkim": parsed.auth.dkim,
            "dmarc": parsed.auth.dmarc,
        },
        "from_addr": _addr_dict(parsed.from_addr),
        "reply_to": _addr_dict(parsed.reply_to),
        "return_path": _addr_dict(parsed.return_path),
        "sender": _addr_dict(parsed.sender),
        "to_addrs": parsed.to_addrs,
        "subject": parsed.subject,
        "message_id": parsed.message_id,
        "date": parsed.date,
        "body_text": parsed.body_text,
        "body_html": parsed.body_html,
        "body_links": [
            {"display_text": link.display_text, "href": link.href}
            for link in parsed.body_links
        ],
        "attachments": [
            {
                "filename": att.filename,
                "content_type": att.content_type,
                "size_bytes": att.size_bytes,
                "sha256": att.sha256,
                "is_inline": att.is_inline,
            }
            for att in parsed.attachments
        ],
        "content_profile": parsed.content_profile,
        "precedence": parsed.precedence,
        "list_unsubscribe": parsed.list_unsubscribe,
    }


def parsed_email_from_dict(data: dict[str, Any]) -> ParsedEmail:
    """Reconstruct ParsedEmail from vendor_block dict."""
    auth_data = data.get("auth") or {}
    parsed = ParsedEmail(
        headers=data.get("headers") or {},
        received_hops=[
            ReceivedHop(
                raw=h.get("raw", ""),
                by_host=h.get("by_host"),
                from_host=h.get("from_host"),
                ip=h.get("ip"),
                date=h.get("date"),
            )
            for h in data.get("received_hops") or []
        ],
        auth=AuthResults(
            spf=auth_data.get("spf", "none"),
            dkim=auth_data.get("dkim", "none"),
            dmarc=auth_data.get("dmarc", "none"),
        ),
        from_addr=_addr_from_dict(data.get("from_addr")),
        reply_to=_addr_from_dict(data.get("reply_to")),
        return_path=_addr_from_dict(data.get("return_path")),
        sender=_addr_from_dict(data.get("sender")),
        to_addrs=data.get("to_addrs") or [],
        subject=data.get("subject"),
        message_id=data.get("message_id"),
        date=data.get("date"),
        body_text=data.get("body_text"),
        body_html=data.get("body_html"),
        body_links=[
            EmailLink(
                display_text=link.get("display_text", ""),
                href=link.get("href", ""),
            )
            for link in data.get("body_links") or []
        ],
        attachments=[
            ParsedAttachment(
                filename=att.get("filename", ""),
                content_type=att.get("content_type", ""),
                size_bytes=int(att.get("size_bytes", 0)),
                sha256=att.get("sha256", ""),
                is_inline=bool(att.get("is_inline")),
            )
            for att in data.get("attachments") or []
        ],
        content_profile=data.get("content_profile") or "headers_only",
        precedence=data.get("precedence"),
        list_unsubscribe=bool(data.get("list_unsubscribe")),
    )
    if not parsed.body_links and parsed.body_html:
        parsed.body_links = extract_links_from_html(parsed.body_html)
    if parsed.content_profile == "headers_only":
        parsed.content_profile = _detect_content_profile(parsed)
    return parsed


def _addr_dict(addr: ParsedAddress | dict[str, Any] | None) -> dict[str, Any] | None:
    if addr is None:
        return None
    if isinstance(addr, dict):
        return addr
    return {
        "raw": addr.raw,
        "display_name": addr.display_name,
        "email": addr.email,
        "domain": addr.domain,
    }


def _addr_from_dict(data: dict[str, Any] | None) -> ParsedAddress | None:
    if not data:
        return None
    return ParsedAddress(
        raw=data.get("raw", ""),
        display_name=data.get("display_name", ""),
        email=data.get("email", ""),
        domain=data.get("domain"),
    )


def link_href_domain(href: str) -> str | None:
    try:
        parsed = urlparse(href.strip())
    except ValueError:
        return None
    if parsed.hostname:
        return parsed.hostname.lower()
    return None
