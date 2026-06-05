from __future__ import annotations

import json
import re
from typing import Any

# Spazi Unicode frequenti in copia-incolla da Word, PDF, chat
_UNICODE_SPACES = (
    "\u00a0",  # NBSP
    "\u2007",
    "\u202f",
    "\u2009",
    "\u200a",
    "\ufeff",  # BOM (anche in mezzo al testo)
)

_SMART_QUOTES = {
    "\u201c": '"',
    "\u201d": '"',
    "\u2018": "'",
    "\u2019": "'",
}


def normalize_pasted_text(text: str) -> str:
    """Pulisce testo incollato da GUI / email / documenti Windows."""
    content = text.strip()
    if content.startswith("\ufeff"):
        content = content.lstrip("\ufeff").strip()
    for ch in _UNICODE_SPACES:
        content = content.replace(ch, " ")
    for old, new in _SMART_QUOTES.items():
        content = content.replace(old, new)
    # Spazi multipli (non toccare newline)
    content = re.sub(r"[^\S\n]+", " ", content)
    return content.strip()


def unwrap_outer_json_string(content: str) -> str:
    """Se l'input è un literal JSON string, estrae il contenuto interno."""
    if len(content) < 2:
        return content
    if (content[0] == '"' and content[-1] == '"') or (
        content[0] == "'" and content[-1] == "'"
    ):
        try:
            inner = json.loads(content)
            if isinstance(inner, str):
                return inner.strip()
        except json.JSONDecodeError:
            pass
    return content


def extract_json_blob(content: str) -> str | None:
    """Estrae il blocco JSON tra la prima { e l'ultima } (o [ ])."""
    for open_ch, close_ch in (("{", "}"), ("[", "]")):
        start = content.find(open_ch)
        end = content.rfind(close_ch)
        if start >= 0 and end > start:
            return content[start : end + 1]
    return None


def _fix_doubled_quotes(content: str) -> str:
    """Corregge virgolette raddoppiate tipiche del copia-incolla (es. {""key"":})."""
    if '""' not in content:
        return content
    if content.startswith('{"') or '""' in content[:80]:
        return content.replace('""', '"')
    return content


def parse_json_lenient(content: str) -> Any:
    """
    Prova più strategie per interpretare JSON incollato in modo difettoso.
    """
    candidates: list[str] = []
    seen: set[str] = set()

    def add(s: str) -> None:
        s = s.strip()
        if s and s not in seen:
            seen.add(s)
            candidates.append(s)

    normalized = normalize_pasted_text(content)
    add(normalized)
    add(unwrap_outer_json_string(normalized))
    unwrapped = unwrap_outer_json_string(normalized)
    if unwrapped != normalized:
        add(normalize_pasted_text(unwrapped))

    blob = extract_json_blob(normalized)
    if blob:
        add(blob)
        add(_fix_doubled_quotes(blob))

    last_error: json.JSONDecodeError | None = None
    for candidate in candidates:
        for attempt in (candidate, _fix_doubled_quotes(candidate)):
            try:
                return json.loads(attempt)
            except json.JSONDecodeError as exc:
                last_error = exc

    hint = (
        "Il testo non è JSON valido. Incolla solo il blocco che inizia con { "
        '(es. {"MicrosoftGraph":...} o {"Cynet":...}) senza virgolette esterne.'
    )
    if last_error:
        raise ValueError(f"{hint} Dettaglio: {last_error}") from last_error
    raise ValueError(hint)


def looks_like_json(content: str) -> bool:
    c = content.lstrip()
    return c.startswith("{") or c.startswith("[") or c.startswith('"{') or c.startswith("'{")


def looks_like_cef(content: str) -> bool:
    return "CEF:" in content.upper().replace("\u00a0", " ")


_EMAIL_HEADER_MARKERS = (
    "from:",
    "received:",
    "message-id:",
    "mime-version:",
    "authentication-results:",
    "return-path:",
    "subject:",
)


def looks_like_email_headers(content: str) -> bool:
    """True if text looks like pasted RFC 5322 email headers."""
    lower = content.lower()
    hits = sum(1 for marker in _EMAIL_HEADER_MARKERS if marker in lower)
    return hits >= 2
