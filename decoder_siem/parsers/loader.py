from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from decoder_siem.parser import get_vendor_block, parse_nested_json_strings
from decoder_siem.parsers.cef import is_fortigate_cef, parse_cef_line

CEF_WRAPPER_KEYS = ("message", "raw", "log", "event", "cef", "syslog")


@dataclass
class LoadedDocument:
    format: Literal["json", "cef"]
    vendor: str | None
    data: Any
    vendor_block: dict[str, Any] | None = None
    raw_event: dict[str, Any] | None = None


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


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


def load_document(path: Path) -> LoadedDocument:
    text = _read_text(path)
    suffix = path.suffix.lower()

    # Try JSON first for .json or content starting with { or [
    if suffix == ".json" or text.startswith("{") or text.startswith("["):
        try:
            raw = json.loads(text)
            cef_string = _extract_cef_from_json(raw)
            if cef_string:
                return _parse_cef_text(cef_string)

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
        except json.JSONDecodeError:
            if suffix == ".json":
                raise
            # Fall through to CEF for misnamed files

    if "CEF:" in text:
        return _parse_cef_text(text)

    raise ValueError(
        f"Unrecognized format in {path}: expected JSON or syslog/CEF line"
    )


def prepare_incident_data(path: Path) -> tuple[Any, str | None, dict[str, Any] | None]:
    """Backward-compatible wrapper for tests and legacy callers."""
    doc = load_document(path)
    return doc.data, doc.vendor, doc.vendor_block
