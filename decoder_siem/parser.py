from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_json_file(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    return json.loads(text)


def parse_nested_json_strings(obj: Any, _path: str = "") -> Any:
    """Parse string values that look like embedded JSON objects."""
    if isinstance(obj, dict):
        result: dict[str, Any] = {}
        for key, value in obj.items():
            child_path = f"{_path}.{key}" if _path else key
            if key == "IncidentJsonDescription" and isinstance(value, str):
                try:
                    result[key] = json.loads(value)
                    result[f"{key}__parsed"] = True
                except json.JSONDecodeError:
                    result[key] = value
            else:
                result[key] = parse_nested_json_strings(value, child_path)
        return result
    if isinstance(obj, list):
        return [parse_nested_json_strings(item, _path) for item in obj]
    return obj


def get_vendor_block(data: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    if not isinstance(data, dict):
        return None, None
    if "Cynet" in data and isinstance(data["Cynet"], dict):
        return "Cynet", data["Cynet"]
    if "MicrosoftGraph" in data and isinstance(data["MicrosoftGraph"], dict):
        return "MicrosoftDefender", data["MicrosoftGraph"]
    for key, value in data.items():
        if isinstance(value, dict) and any(
            k in value
            for k in (
                "IncidentName",
                "HostIp",
                "IncidentJsonDescription",
                "IncidentDescription",
            )
        ):
            return key, value
    return None, None


def prepare_incident_data(path: Path) -> tuple[Any, str | None, dict[str, Any] | None]:
    """Backward-compatible; prefer decoder_siem.parsers.loader.load_document."""
    from decoder_siem.parsers.loader import load_document

    doc = load_document(path)
    return doc.data, doc.vendor, doc.vendor_block
