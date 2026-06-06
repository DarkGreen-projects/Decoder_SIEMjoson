from __future__ import annotations

import ipaddress
import re
from typing import Any

from decoder_siem.input_guard import validate_artifact_value
from decoder_siem.models import Artifact, ArtifactScope, ArtifactType
from decoder_siem.parsers.normalize import (
    looks_like_cef,
    looks_like_email_headers,
    looks_like_json,
)

_IOC_SEP_RE = re.compile(r"[\s,;]+")
_SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
_SHA1_RE = re.compile(r"^[A-Fa-f0-9]{40}$")
_MD5_RE = re.compile(r"^[A-Fa-f0-9]{32}$")
_URL_RE = re.compile(r"^https?://[^\s\"'<>]+$", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)

_DOMAIN_SKIP_SUFFIXES = (".app", ".pdf", ".exe", ".dll", ".json")


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
    )


def _make_ioc_artifact(
    artifact_type: ArtifactType,
    value: str,
    provenance: str,
) -> Artifact:
    value = validate_artifact_value(value)
    if artifact_type == ArtifactType.IP:
        norm = value.strip()
        scope = ArtifactScope.INTERNAL if _is_private_ip(norm) else ArtifactScope.PUBLIC
    elif artifact_type in (
        ArtifactType.HASH_SHA256,
        ArtifactType.HASH_SHA1,
        ArtifactType.HASH_MD5,
    ):
        norm = value.upper()
        scope = ArtifactScope.PUBLIC
    elif artifact_type == ArtifactType.DOMAIN:
        norm = value.lower().rstrip(".")
        scope = ArtifactScope.PUBLIC
    else:
        norm = value
        scope = ArtifactScope.PUBLIC

    return Artifact(
        type=artifact_type,
        value=value,
        normalized_value=norm,
        scope=scope,
        provenance=[provenance],
        context={},
    )


def _deduplicate_artifacts(artifacts: list[Artifact]) -> list[Artifact]:
    merged: dict[tuple[ArtifactType, str], Artifact] = {}
    for art in artifacts:
        key = (art.type, art.normalized_value)
        if key in merged:
            existing = merged[key]
            for prov in art.provenance:
                if prov not in existing.provenance:
                    existing.provenance.append(prov)
            if art.scope == ArtifactScope.INTERNAL:
                existing.scope = ArtifactScope.INTERNAL
        else:
            merged[key] = art.model_copy(deep=True)
    return list(merged.values())


def tokenize_ioc_input(text: str) -> list[str]:
    tokens: list[str] = []
    for part in _IOC_SEP_RE.split(text.strip()):
        part = part.strip()
        if part:
            tokens.append(part)
    return tokens


def classify_ioc_token(token: str) -> Artifact | None:
    value = token.strip()
    if not value:
        return None

    lower = value.lower()
    if lower.startswith(("http://", "https://")) or _URL_RE.fullmatch(value):
        return _make_ioc_artifact(ArtifactType.URL, value, "ioc:token")

    try:
        ipaddress.ip_address(value)
        return _make_ioc_artifact(ArtifactType.IP, value, "ioc:token")
    except ValueError:
        pass

    if _SHA256_RE.fullmatch(value):
        return _make_ioc_artifact(ArtifactType.HASH_SHA256, value, "ioc:token")
    if _SHA1_RE.fullmatch(value):
        return _make_ioc_artifact(ArtifactType.HASH_SHA1, value, "ioc:token")
    if _MD5_RE.fullmatch(value):
        return _make_ioc_artifact(ArtifactType.HASH_MD5, value, "ioc:token")

    if _DOMAIN_RE.fullmatch(value):
        domain = value
        if domain.replace(".", "").isdigit():
            return None
        if any(domain.endswith(suffix) for suffix in _DOMAIN_SKIP_SUFFIXES):
            return None
        return _make_ioc_artifact(ArtifactType.DOMAIN, domain, "ioc:token")

    return None


def looks_like_ioc_list(text: str) -> bool:
    if looks_like_json(text) or looks_like_cef(text) or looks_like_email_headers(text):
        return False
    tokens = tokenize_ioc_input(text)
    if not tokens:
        return False
    return all(classify_ioc_token(token) is not None for token in tokens)


def artifacts_from_ioc_tokens(tokens: list[str]) -> list[Artifact]:
    artifacts: list[Artifact] = []
    for idx, token in enumerate(tokens):
        art = classify_ioc_token(token)
        if art is None:
            continue
        art.provenance = [f"ioc[{idx}]"]
        artifacts.append(art)
    return _deduplicate_artifacts(artifacts)


def artifacts_from_ioc_document(data: Any) -> list[Artifact]:
    if isinstance(data, dict):
        tokens = data.get("tokens") or []
        if isinstance(tokens, list):
            return artifacts_from_ioc_tokens([str(t) for t in tokens])
    return []


def parse_ioc_list(text: str) -> "LoadedDocument":
    from decoder_siem.parsers.loader import LoadedDocument

    tokens = tokenize_ioc_input(text)
    artifacts = artifacts_from_ioc_tokens(tokens)
    if not artifacts:
        raise ValueError("Nessun IOC valido trovato nell'input.")

    block: dict[str, Any] = {
        "tokens": tokens,
        "raw_text": text,
        "ioc_count": len(artifacts),
        "input_mode": "direct",
    }
    return LoadedDocument(
        format="ioc",
        vendor="RawIOC",
        data=block,
        vendor_block=block,
        raw_event=block,
    )
