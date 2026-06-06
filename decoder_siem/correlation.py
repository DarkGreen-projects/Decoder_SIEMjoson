from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from decoder_siem.models import Artifact, ArtifactReport, ArtifactType

HASH_TYPES = {
    ArtifactType.HASH_SHA256,
    ArtifactType.HASH_SHA1,
    ArtifactType.HASH_MD5,
}

FILE_CORRELATED_ROLES = frozenset(
    {
        "infected_file",
        "download_url",
    }
)

ENTITY_ROLE_LABELS_IT = {
    "infected_file": "file infetto",
    "parent_process": "proc. padre",
    "grandparent_process": "proc. nonno",
    "process": "processo",
    "download_url": "URL download",
    "network": "rete",
    "standalone": "",
}

_PROVENANCE_FIELD_RE = re.compile(r"^(.*)\.[^.\[]+$")


def basename_from_path(path: str) -> str | None:
    text = path.strip().rstrip("/\\")
    if not text:
        return None
    return os.path.basename(text) or None


def entity_role_label(role: str | None) -> str:
    if not role:
        return ""
    return ENTITY_ROLE_LABELS_IT.get(role, role.replace("_", " "))


@dataclass
class CorrelatedEntity:
    id: str
    role: str
    hash_artifact: Artifact | None = None
    path_artifact: Artifact | None = None
    url_artifacts: list[Artifact] = field(default_factory=list)
    domain_artifacts: list[Artifact] = field(default_factory=list)
    display_name: str | None = None

    def has_hash(self) -> bool:
        return self.hash_artifact is not None


def _provenance_prefix(provenance: str) -> str | None:
    match = _PROVENANCE_FIELD_RE.match(provenance)
    if not match:
        return None
    return match.group(1)


def _get_or_create_entity(
    entities: dict[str, CorrelatedEntity],
    group_id: str,
    role: str,
) -> CorrelatedEntity:
    if group_id not in entities:
        entities[group_id] = CorrelatedEntity(id=group_id, role=role)
    entity = entities[group_id]
    if entity.role == "standalone" and role != "standalone":
        entity.role = role
    return entity


def _attach_artifact(entity: CorrelatedEntity, art: Artifact) -> None:
    if art.type in HASH_TYPES:
        if entity.hash_artifact is None:
            entity.hash_artifact = art
        return
    if art.type == ArtifactType.FILE_PATH:
        if entity.path_artifact is None:
            entity.path_artifact = art
            entity.display_name = basename_from_path(art.value)
        return
    if art.type == ArtifactType.URL:
        if art not in entity.url_artifacts:
            entity.url_artifacts.append(art)
        return
    if art.type == ArtifactType.DOMAIN:
        if art not in entity.domain_artifacts:
            entity.domain_artifacts.append(art)


def _fallback_group_from_provenance(provenance: str) -> str | None:
    if ":regex" in provenance:
        return provenance.rsplit(":regex", 1)[0]
    return _provenance_prefix(provenance)


def build_correlated_entities(
    artifact_reports: list[ArtifactReport],
) -> list[CorrelatedEntity]:
    entities: dict[str, CorrelatedEntity] = {}
    fallback_buckets: dict[str, list[Artifact]] = {}

    for ar in artifact_reports:
        art = ar.artifact
        group_id = art.context.get("correlation_group")
        role = art.context.get("entity_role") or "standalone"

        if group_id:
            entity = _get_or_create_entity(entities, str(group_id), str(role))
            _attach_artifact(entity, art)
            continue

        if art.type in HASH_TYPES | {ArtifactType.FILE_PATH, ArtifactType.URL, ArtifactType.DOMAIN}:
            for prov in art.provenance:
                prefix = _fallback_group_from_provenance(prov)
                if prefix:
                    fallback_buckets.setdefault(prefix, []).append(art)

    for prefix, arts in fallback_buckets.items():
        hashes = [a for a in arts if a.type in HASH_TYPES]
        paths = [a for a in arts if a.type == ArtifactType.FILE_PATH]
        urls = [a for a in arts if a.type == ArtifactType.URL]
        domains = [a for a in arts if a.type == ArtifactType.DOMAIN]
        if not hashes:
            continue
        role = "infected_file" if paths else "standalone"
        entity = _get_or_create_entity(entities, f"fallback:{prefix}", role)
        for art in hashes:
            _attach_artifact(entity, art)
        for art in paths:
            _attach_artifact(entity, art)
        for art in urls:
            _attach_artifact(entity, art)
        for art in domains:
            _attach_artifact(entity, art)

    return list(entities.values())


def find_entity_for_artifact(
    artifact: Artifact,
    entities: list[CorrelatedEntity],
) -> CorrelatedEntity | None:
    group_id = artifact.context.get("correlation_group")
    if group_id:
        for entity in entities:
            if entity.id == group_id:
                return entity

    for prov in artifact.provenance:
        prefix = _fallback_group_from_provenance(prov)
        if prefix:
            fallback_id = f"fallback:{prefix}"
            for entity in entities:
                if entity.id == fallback_id:
                    return entity
    return None


def should_skip_enrichment(
    artifact: Artifact,
    entities: list[CorrelatedEntity],
) -> str | None:
    entity = find_entity_for_artifact(artifact, entities)
    if entity is None or not entity.has_hash():
        return None

    role = artifact.context.get("entity_role") or entity.role

    if artifact.type == ArtifactType.FILE_PATH:
        return "Percorso coperto da analisi VT sull'hash correlato"

    if artifact.type == ArtifactType.URL:
        if role in FILE_CORRELATED_ROLES or entity.role in FILE_CORRELATED_ROLES:
            return "URL/dominio correlato a file già analizzato via hash"
        if entity.path_artifact is not None:
            return "URL/dominio correlato a file già analizzato via hash"

    if artifact.type == ArtifactType.DOMAIN:
        if role in FILE_CORRELATED_ROLES:
            return "URL/dominio correlato a file già analizzato via hash"

    return None


def entity_facts_from_report(
    report: IncidentReport,
    entities: list[CorrelatedEntity] | None = None,
) -> list[dict[str, str | None]]:
    from decoder_siem.table_export import classify_artifact

    if entities is None:
        entities = build_correlated_entities(report.artifacts)

    facts: list[dict[str, str | None]] = []
    for entity in entities:
        hash_val = entity.hash_artifact.normalized_value if entity.hash_artifact else None
        path_val = entity.path_artifact.value if entity.path_artifact else None
        vt_verdict = None
        if entity.hash_artifact:
            for ar in report.artifacts:
                if ar.artifact.normalized_value == entity.hash_artifact.normalized_value:
                    if ar.artifact.type == entity.hash_artifact.type:
                        vt_verdict = classify_artifact(ar)
                        break
        facts.append(
            {
                "role": entity.role,
                "role_label": entity_role_label(entity.role),
                "display_name": entity.display_name,
                "path": path_val,
                "hash": hash_val,
                "vt_verdict": vt_verdict,
            }
        )
    return facts
