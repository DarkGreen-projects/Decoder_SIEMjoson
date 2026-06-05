from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr
from typing import Any

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
    precedence: str | None = None
    list_unsubscribe: bool = False


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


def _header_values(msg: Any, name: str) -> list[str]:
    values: list[str] = []
    if msg is None:
        return values
    raw = msg.get_all(name) if hasattr(msg, "get_all") else None
    if not raw:
        single = msg.get(name) if hasattr(msg, "get") else None
        if single:
            raw = [single]
    if raw:
        for item in raw:
            if item:
                values.append(str(item).strip())
    return values


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


def _extract_body_text(msg: Any) -> str | None:
    if msg is None:
        return None
    try:
        if msg.is_multipart():
            parts: list[str] = []
            for part in msg.walk():
                if part.get_content_disposition() == "attachment":
                    continue
                ctype = part.get_content_type()
                if ctype == "text/plain":
                    payload = part.get_content()
                    if isinstance(payload, str) and payload.strip():
                        parts.append(payload)
            return "\n".join(parts) if parts else None
        payload = msg.get_content()
        if isinstance(payload, str):
            return payload
    except Exception:  # noqa: BLE001
        return None
    return None


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
    parsed.body_text = _extract_body_text(msg)
    return parsed


def _first(headers: dict[str, list[str]], key: str) -> str | None:
    values = headers.get(key)
    if values:
        return values[0]
    return None


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
        precedence=data.get("precedence"),
        list_unsubscribe=bool(data.get("list_unsubscribe")),
    )
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
