from __future__ import annotations

import json
from typing import Any

from decoder_siem.extractors.patterns import (
    DOMAIN_RE,
    IPV4_RE,
    MD5_RE,
    SHA1_RE,
    SHA256_RE,
    URL_RE,
    is_private_ip,
    normalize_domain,
    normalize_hash,
    normalize_ip,
)
from decoder_siem.input_guard import max_artifacts, max_string_scan_len, validate_artifact_value
from decoder_siem.models import Artifact, ArtifactScope, ArtifactType

def _max_walk_nodes() -> int:
    return max_artifacts() * 50

HASH_FIELD_HINTS = ("sha256", "sha1", "md5", "hash")
IP_FIELD_HINTS = ("ip", "hostip", "alertip")
PATH_FIELD_HINTS = ("path", "file", "commandline")
DOMAIN_FIELD_HINTS = ("domain", "alertdomain")
URL_FIELD_HINTS = ("url", "alerturl")


def _artifact_scope_for_ip(ip: str) -> ArtifactScope:
    return ArtifactScope.INTERNAL if is_private_ip(ip) else ArtifactScope.PUBLIC


def _make_artifact(
    artifact_type: ArtifactType,
    value: str,
    provenance: str,
    *,
    normalized: str | None = None,
    scope: ArtifactScope | None = None,
    context: dict[str, Any] | None = None,
) -> Artifact:
    value = validate_artifact_value(value)
    if artifact_type == ArtifactType.IP:
        norm = normalized or normalize_ip(value)
        art_scope = scope or _artifact_scope_for_ip(norm)
    elif artifact_type in (
        ArtifactType.HASH_SHA256,
        ArtifactType.HASH_SHA1,
        ArtifactType.HASH_MD5,
    ):
        norm = normalized or normalize_hash(value)
        art_scope = scope or ArtifactScope.PUBLIC
    elif artifact_type == ArtifactType.DOMAIN:
        norm = normalized or normalize_domain(value)
        art_scope = scope or ArtifactScope.PUBLIC
    else:
        norm = normalized or value
        art_scope = scope or ArtifactScope.PUBLIC

    return Artifact(
        type=artifact_type,
        value=value,
        normalized_value=norm,
        scope=art_scope,
        provenance=[provenance],
        context=context or {},
    )


def _field_name_matches(name: str, hints: tuple[str, ...]) -> bool:
    lower = name.lower().replace(" ", "")
    return any(h in lower for h in hints)


class GenericExtractor:
    def __init__(self) -> None:
        self._nodes_visited = 0

    def extract(self, data: Any, base_path: str = "root") -> list[Artifact]:
        artifacts: list[Artifact] = []
        self._nodes_visited = 0
        self._walk(data, base_path, artifacts)
        return artifacts

    def _walk(self, obj: Any, path: str, out: list[Artifact]) -> None:
        self._nodes_visited += 1
        if self._nodes_visited > _max_walk_nodes():
            return
        if len(out) >= max_artifacts():
            return
        if isinstance(obj, dict):
            for key, value in obj.items():
                child_path = f"{path}.{key}"
                if isinstance(value, str):
                    out.extend(self._from_string(value, child_path))
                    if _field_name_matches(key, HASH_FIELD_HINTS):
                        out.extend(self._hash_from_field(key, value, child_path))
                    elif _field_name_matches(key, IP_FIELD_HINTS):
                        if IPV4_RE.fullmatch(value.strip()) or self._looks_like_ip(value):
                            out.append(
                                _make_artifact(
                                    ArtifactType.IP,
                                    value.strip(),
                                    child_path,
                                )
                            )
                    elif _field_name_matches(key, PATH_FIELD_HINTS) and value.strip():
                        if not value.startswith("http"):
                            out.append(
                                _make_artifact(
                                    ArtifactType.FILE_PATH,
                                    value,
                                    child_path,
                                )
                            )
                    elif _field_name_matches(key, DOMAIN_FIELD_HINTS) and value.strip():
                        out.append(
                            _make_artifact(
                                ArtifactType.DOMAIN,
                                value,
                                child_path,
                            )
                        )
                    elif _field_name_matches(key, URL_FIELD_HINTS) and value.strip():
                        out.append(
                            _make_artifact(ArtifactType.URL, value, child_path)
                        )
                else:
                    self._walk(value, child_path, out)
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                self._walk(item, f"{path}[{idx}]", out)
        elif isinstance(obj, str):
            out.extend(self._from_string(obj, path))

    def _looks_like_ip(self, value: str) -> bool:
        try:
            import ipaddress

            ipaddress.ip_address(value.strip())
            return True
        except ValueError:
            return False

    def _hash_from_field(
        self, key: str, value: str, path: str
    ) -> list[Artifact]:
        lower = key.lower()
        if len(value) == 64 or "sha256" in lower:
            return [
                _make_artifact(ArtifactType.HASH_SHA256, value, path)
            ]
        if len(value) == 40 or "sha1" in lower:
            return [_make_artifact(ArtifactType.HASH_SHA1, value, path)]
        if len(value) == 32 or "md5" in lower:
            return [_make_artifact(ArtifactType.HASH_MD5, value, path)]
        return self._from_string(value, path)

    def _from_string(self, text: str, path: str) -> list[Artifact]:
        if len(text) > max_string_scan_len():
            return []
        found: list[Artifact] = []
        for match in SHA256_RE.finditer(text):
            found.append(
                _make_artifact(
                    ArtifactType.HASH_SHA256, match.group(0), f"{path}:regex"
                )
            )
        for match in SHA1_RE.finditer(text):
            val = match.group(0)
            if SHA256_RE.fullmatch(val):
                continue
            found.append(
                _make_artifact(ArtifactType.HASH_SHA1, val, f"{path}:regex")
            )
        for match in MD5_RE.finditer(text):
            val = match.group(0)
            if SHA1_RE.fullmatch(val) or SHA256_RE.fullmatch(val):
                continue
            found.append(
                _make_artifact(ArtifactType.HASH_MD5, val, f"{path}:regex")
            )
        for match in IPV4_RE.finditer(text):
            found.append(
                _make_artifact(ArtifactType.IP, match.group(0), f"{path}:regex")
            )
        for match in URL_RE.finditer(text):
            found.append(
                _make_artifact(ArtifactType.URL, match.group(0), f"{path}:regex")
            )
        for match in DOMAIN_RE.finditer(text):
            domain = match.group(0)
            if domain.replace(".", "").isdigit():
                continue
            if any(
                domain.endswith(suffix)
                for suffix in (".app", ".pdf", ".exe", ".dll", ".json")
            ):
                continue
            found.append(
                _make_artifact(ArtifactType.DOMAIN, domain, f"{path}:regex")
            )
        return found


def deduplicate_artifacts(artifacts: list[Artifact]) -> list[Artifact]:
    merged: dict[tuple[ArtifactType, str], Artifact] = {}
    for art in artifacts:
        key = (art.type, art.normalized_value)
        if key in merged:
            existing = merged[key]
            for prov in art.provenance:
                if prov not in existing.provenance:
                    existing.provenance.append(prov)
            existing.context.update(art.context)
            if art.scope == ArtifactScope.INTERNAL:
                existing.scope = ArtifactScope.INTERNAL
        else:
            merged[key] = art.model_copy(deep=True)
    return list(merged.values())


def merge_artifacts(*groups: list[Artifact]) -> list[Artifact]:
    combined: list[Artifact] = []
    for group in groups:
        combined.extend(group)
    return deduplicate_artifacts(combined)


def artifacts_to_json_debug(artifacts: list[Artifact]) -> str:
    return json.dumps(
        [a.model_dump() for a in artifacts],
        indent=2,
        ensure_ascii=False,
    )
