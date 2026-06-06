from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

_DEFAULT_CACHE_ROOT = Path.home() / ".local" / "share" / "decoder_siem"

_ALLOWED_ENRICHERS = frozenset(
    {"virustotal", "otx", "urlhaus", "abuseipdb", "correlation", "trusted"}
)

_DANGEROUS_MD_LINK = re.compile(r"\]\(\s*javascript:", re.IGNORECASE)


class InputSecurityError(ValueError):
    """Input rifiutato per motivi di sicurezza o dimensione."""


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def max_input_chars() -> int:
    return _env_int("DECODER_MAX_INPUT_CHARS", 2_000_000)


def max_file_bytes() -> int:
    return _env_int("DECODER_MAX_FILE_BYTES", 20_000_000)


def max_json_depth() -> int:
    return _env_int("DECODER_MAX_JSON_DEPTH", 64)


def max_json_decode_passes() -> int:
    return _env_int("DECODER_MAX_JSON_DECODE_PASSES", 5)


def max_artifacts() -> int:
    return _env_int("DECODER_MAX_ARTIFACTS", 500)


def max_ioc_value_len() -> int:
    return _env_int("DECODER_MAX_IOC_VALUE_LEN", 4096)


def max_string_scan_len() -> int:
    return _env_int("DECODER_MAX_STRING_SCAN_LEN", 65536)


def max_email_attachments() -> int:
    return _env_int("DECODER_MAX_EMAIL_ATTACHMENTS", 20)


def max_email_attachment_bytes() -> int:
    return _env_int("DECODER_MAX_EMAIL_ATTACHMENT_BYTES", 5_000_000)


def _reject_disallowed_control_chars(text: str) -> None:
    for ch in text:
        code = ord(ch)
        if code == 0:
            raise InputSecurityError("Input contiene caratteri non consentiti.")
        if code < 32 and ch not in ("\n", "\r", "\t"):
            raise InputSecurityError("Input contiene caratteri di controllo non consentiti.")


def validate_text_input(text: str, *, source: str = "input") -> str:
    if not text or not text.strip():
        raise InputSecurityError("Input vuoto.")
    if len(text) > max_input_chars():
        raise InputSecurityError(
            f"Input troppo grande (max {max_input_chars()} caratteri) in {source}."
        )
    _reject_disallowed_control_chars(text)
    return text


def validate_file_path(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise InputSecurityError(f"File non trovato o non valido: {path}")
    size = resolved.stat().st_size
    if size > max_file_bytes():
        raise InputSecurityError(
            f"File troppo grande (max {max_file_bytes()} byte): {path}"
        )
    return resolved


def read_bounded_text(path: Path) -> str:
    validated = validate_file_path(path)
    raw = validated.read_bytes()
    if len(raw) > max_file_bytes():
        raise InputSecurityError(
            f"File troppo grande (max {max_file_bytes()} byte): {path}"
        )
    return raw.decode("utf-8", errors="replace").strip()


def validate_cache_db_path(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    if resolved.suffix.lower() not in (".db", ".sqlite", ".sqlite3"):
        raise InputSecurityError(
            "Percorso cache deve essere un file database (.db, .sqlite)."
        )
    default_root = _DEFAULT_CACHE_ROOT.resolve()
    try:
        resolved.relative_to(default_root)
    except ValueError:
        parent = resolved.parent
        if not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)
        if not os.access(parent, os.W_OK):
            raise InputSecurityError(
                "Percorso cache non scrivibile o fuori directory consentita."
            )
    return resolved


def check_json_depth(obj: Any, *, max_depth: int | None = None) -> None:
    limit = max_depth if max_depth is not None else max_json_depth()

    def _walk(value: Any, depth: int) -> None:
        if depth > limit:
            raise InputSecurityError(
                f"JSON troppo annidato (max profondità {limit})."
            )
        if isinstance(value, dict):
            for item in value.values():
                _walk(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                _walk(item, depth + 1)

    _walk(obj, 0)


def loads_json_bounded(raw: str) -> Any:
    if len(raw) > max_input_chars():
        raise InputSecurityError("JSON troppo grande.")
    _reject_disallowed_control_chars(raw)
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(str(exc)) from exc
    check_json_depth(obj)
    return obj


def validate_artifact_value(value: str) -> str:
    if not isinstance(value, str):
        value = str(value)
    if len(value) > max_ioc_value_len():
        raise InputSecurityError(
            f"Valore IOC troppo lungo (max {max_ioc_value_len()} caratteri)."
        )
    _reject_disallowed_control_chars(value)
    return value


def validate_enricher_name(name: str) -> str:
    if name not in _ALLOWED_ENRICHERS:
        raise InputSecurityError(f"Enricher non consentito: {name}")
    return name


def sanitize_markdown_text(value: str | None) -> str:
    if value is None:
        return ""
    text = str(value)
    text = (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    return _DANGEROUS_MD_LINK.sub("](", text)


def safe_md(value: str | None) -> str:
    """Alias per sanitizzazione campi utente in Markdown."""
    return sanitize_markdown_text(value)
