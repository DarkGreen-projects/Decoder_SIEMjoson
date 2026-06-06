from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from decoder_siem.input_guard import (
    InputSecurityError,
    max_json_decode_passes,
    read_bounded_text,
    validate_text_input,
)
from decoder_siem.parser import get_vendor_block, parse_nested_json_strings
from decoder_siem.parsers.cef import is_fortigate_cef, parse_cef_line
from decoder_siem.parsers.email import (
    looks_like_mime_message,
    parse_email_headers,
    parse_email_message,
    parsed_email_to_dict,
)
from decoder_siem.parsers.ioc_list import looks_like_ioc_list, parse_ioc_list
from decoder_siem.parsers.normalize import (
    looks_like_cef,
    looks_like_email_headers,
    looks_like_json,
    normalize_pasted_text,
    parse_json_lenient,
)

CEF_WRAPPER_KEYS = ("message", "raw", "log", "event", "cef", "syslog")


DocumentFormat = Literal["json", "cef", "email", "ioc"]


@dataclass
class LoadedDocument:
    format: DocumentFormat
    vendor: str | None
    data: Any
    vendor_block: dict[str, Any] | None = None
    raw_event: dict[str, Any] | None = None


def _read_text(path: Path) -> str:
    return read_bounded_text(path)


def _extract_cef_from_json(obj: Any) -> str | None:
    if isinstance(obj, str) and "CEF:" in obj:
        return obj
    if isinstance(obj, dict):
        for key in CEF_WRAPPER_KEYS:
            val = obj.get(key)
            if isinstance(val, str) and "CEF:" in val:
                return val
        for value in obj.values():
            found = _extract_cef_from_json(value)
            if found:
                return found
    if isinstance(obj, list):
        for item in obj:
            found = _extract_cef_from_json(item)
            if found:
                return found
    return None


def _detect_vendor_cef(parsed_cef: dict[str, Any]) -> str | None:
    if is_fortigate_cef(parsed_cef):
        return "FortiGate"
    cef = parsed_cef.get("cef") or {}
    vendor = cef.get("vendor")
    if vendor:
        return str(vendor)
    return None


def _parse_cef_text(text: str) -> LoadedDocument:
    # Multi-line: first line containing CEF
    for line in text.splitlines():
        line = line.strip()
        if "CEF:" in line:
            parsed = parse_cef_line(line)
            vendor = _detect_vendor_cef(parsed)
            return LoadedDocument(
                format="cef",
                vendor=vendor,
                data=parsed,
                vendor_block=parsed,
                raw_event=parsed,
            )
    parsed = parse_cef_line(text)
    vendor = _detect_vendor_cef(parsed)
    return LoadedDocument(
        format="cef",
        vendor=vendor,
        data=parsed,
        vendor_block=parsed,
        raw_event=parsed,
    )


def _load_json_document(raw: Any) -> LoadedDocument:
    cef_string = _extract_cef_from_json(raw)
    if cef_string:
        return _parse_cef_text(normalize_pasted_text(cef_string))

    parsed = parse_nested_json_strings(raw)
    vendor, block = None, None
    if isinstance(parsed, dict):
        vendor, block = get_vendor_block(parsed)
    return LoadedDocument(
        format="json",
        vendor=vendor,
        data=parsed,
        vendor_block=block,
        raw_event=raw if isinstance(raw, dict) else None,
    )


def load_text(text: str, *, source_hint: str | None = None) -> LoadedDocument:
    """Load and detect format from raw text (JSON, CEF/syslog, or wrapped CEF in JSON)."""
    label = source_hint or "input"
    validate_text_input(text, source=label)
    content = normalize_pasted_text(text)
    if not content:
        raise ValueError("Input vuoto: incolla JSON o un log CEF/syslog")

    suffix = ""
    if source_hint and "." in source_hint:
        suffix = Path(source_hint).suffix.lower()

    try_json = (
        suffix == ".json"
        or looks_like_json(content)
        or ("MicrosoftGraph" in content or "Cynet" in content)
    )

    if try_json:
        try:
            raw = parse_json_lenient(content)
            # Doppio encoding: stringa JSON che contiene altro JSON
            passes = 0
            while isinstance(raw, str) and (
                looks_like_json(raw) or "MicrosoftGraph" in raw or "Cynet" in raw
            ):
                passes += 1
                if passes > max_json_decode_passes():
                    raise InputSecurityError(
                        "Troppi livelli di encoding JSON annidati."
                    )
                raw = parse_json_lenient(raw)
            return _load_json_document(raw)
        except InputSecurityError:
            raise
        except ValueError as exc:
            if suffix == ".json":
                raise ValueError(f"JSON non valido: {exc}") from exc
            # Fall through to CEF / email detection

    if looks_like_cef(content):
        return _parse_cef_text(content)

    is_eml = suffix == ".eml"
    if is_eml or looks_like_email_headers(content):
        use_full_mime = is_eml or looks_like_mime_message(content)
        parsed = (
            parse_email_message(content)
            if use_full_mime
            else parse_email_headers(content)
        )
        block = parsed_email_to_dict(parsed)
        return LoadedDocument(
            format="email",
            vendor="EmailHeaders",
            data=block,
            vendor_block=block,
            raw_event=block,
        )

    if looks_like_ioc_list(content):
        return parse_ioc_list(content)

    label = source_hint or "input"
    raise ValueError(
        f"Formato non riconosciuto in {label}. "
        "Incolla un JSON che inizia con { (es. {\"MicrosoftGraph\":...}), "
        "una riga syslog con CEF:, header email (From:, Received:, ...), "
        "oppure uno o più IOC diretti (IP, hash SHA256/SHA1/MD5, URL, dominio) "
        "separati da spazio, virgola o punto e virgola "
        "(es. 1.2.3.4 oppure abc...64, def...64). "
        "Evita testo prima/dopo il JSON e virgolette esterne."
    )


def load_document(path: Path) -> LoadedDocument:
    return load_text(_read_text(path), source_hint=str(path))


def prepare_incident_data(path: Path) -> tuple[Any, str | None, dict[str, Any] | None]:
    """Backward-compatible wrapper for tests and legacy callers."""
    doc = load_document(path)
    return doc.data, doc.vendor, doc.vendor_block
