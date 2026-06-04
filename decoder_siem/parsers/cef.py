from __future__ import annotations

import re
from typing import Any

SYSLOG_CEF_RE = re.compile(
    r"^(?:<(?P<priority>\d+)>)?"
    r"(?:(?P<timestamp>\w{3}\s+\d{1,2}\s+[\d:]+)\s+)?"
    r"(?:(?P<hostname>\S+)\s+)?"
    r"CEF:(?P<cef_body>.+)$",
    re.DOTALL,
)

EXTENSION_KV_RE = re.compile(
    r"(?:^|\s)([A-Za-z0-9_.]+)=(.*?)(?=\s+[A-Za-z0-9_.]+=|$)",
    re.DOTALL,
)


def parse_cef_extension(extension: str) -> dict[str, str]:
    """Parse CEF extension key=value pairs (values may contain spaces)."""
    result: dict[str, str] = {}
    text = extension.strip()
    if not text:
        return result
    for match in EXTENSION_KV_RE.finditer(text):
        key = match.group(1)
        value = match.group(2).strip()
        result[key] = value
    return result


def parse_cef_line(line: str) -> dict[str, Any]:
    """
    Parse a syslog + CEF line into a normalized structure.

    Returns dict with keys: format, syslog, cef.
    """
    text = line.strip()
    if not text:
        raise ValueError("Empty CEF line")

    # Allow raw CEF without syslog prefix
    if not text.upper().startswith("CEF:") and " CEF:" not in text:
        if text.upper().startswith("CEF:"):
            text = text
        else:
            raise ValueError("Line does not contain CEF payload")

    match = SYSLOG_CEF_RE.match(text)
    if not match:
        # Fallback: find CEF: anywhere
        idx = text.find("CEF:")
        if idx < 0:
            raise ValueError("Invalid CEF/syslog format")
        prefix = text[:idx].strip()
        cef_body = text[idx + 4 :]
        syslog: dict[str, Any] = {}
        if prefix.startswith("<"):
            pri_end = prefix.find(">")
            if pri_end > 0:
                syslog["priority"] = int(prefix[1:pri_end])
                prefix = prefix[pri_end + 1 :].strip()
        parts = prefix.split(None, 2)
        if len(parts) >= 2:
            syslog["timestamp"] = f"{parts[0]} {parts[1]}"
        if len(parts) >= 3:
            syslog["hostname"] = parts[2]
    else:
        cef_body = match.group("cef_body")
        syslog = {}
        if match.group("priority"):
            syslog["priority"] = int(match.group("priority"))
        if match.group("timestamp"):
            syslog["timestamp"] = match.group("timestamp")
        if match.group("hostname"):
            syslog["hostname"] = match.group("hostname")

    # Split header (7 pipes) from extension
    pipe_positions: list[int] = []
    for i, ch in enumerate(cef_body):
        if ch == "|":
            pipe_positions.append(i)
            if len(pipe_positions) == 7:
                break

    if len(pipe_positions) < 7:
        raise ValueError(
            f"CEF header requires 7 pipe separators, found {len(pipe_positions)}"
        )

    header_part = cef_body[: pipe_positions[6]]
    extension_part = cef_body[pipe_positions[6] + 1 :]

    header_fields = header_part.split("|")
    if len(header_fields) < 7:
        raise ValueError("CEF header incomplete")

    severity_raw = header_fields[6]
    try:
        severity = int(severity_raw)
    except ValueError:
        severity = severity_raw

    extension = parse_cef_extension(extension_part)

    return {
        "format": "cef",
        "syslog": syslog,
        "cef": {
            "version": header_fields[0],
            "vendor": header_fields[1],
            "product": header_fields[2],
            "device_version": header_fields[3],
            "signature_id": header_fields[4],
            "name": header_fields[5],
            "severity": severity,
            "extension": extension,
        },
    }


def is_fortigate_cef(parsed: dict[str, Any]) -> bool:
    cef = parsed.get("cef") or {}
    vendor = (cef.get("vendor") or "").lower()
    product = (cef.get("product") or "").lower()
    extension = cef.get("extension") or {}
    if vendor == "fortinet" or "fortigate" in product:
        return True
    return any(str(k).startswith("FTNTFGT") for k in extension)
