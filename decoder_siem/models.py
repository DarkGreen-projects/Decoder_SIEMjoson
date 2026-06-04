from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ArtifactType(str, Enum):
    IP = "ip"
    HASH_SHA256 = "hash_sha256"
    HASH_SHA1 = "hash_sha1"
    HASH_MD5 = "hash_md5"
    DOMAIN = "domain"
    URL = "url"
    FILE_PATH = "file_path"
    HOSTNAME = "hostname"
    USERNAME = "username"
    MALWARE_LABEL = "malware_label"
    OTHER = "other"


class ArtifactScope(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"


class Artifact(BaseModel):
    type: ArtifactType
    value: str
    normalized_value: str
    scope: ArtifactScope = ArtifactScope.PUBLIC
    provenance: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)


class EnrichmentStatus(str, Enum):
    SUCCESS = "success"
    SKIPPED = "skipped"
    ERROR = "error"
    NOT_FOUND = "not_found"


class EnrichmentResult(BaseModel):
    enricher: str
    status: EnrichmentStatus
    summary: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class IncidentContext(BaseModel):
    vendor: str | None = None
    incident_name: str | None = None
    host_name: str | None = None
    host_ip: str | None = None
    user_name: str | None = None
    severity: int | None = None
    malware_id: str | None = None
    malware_type: str | None = None
    date_in: str | None = None


class ArtifactReport(BaseModel):
    artifact: Artifact
    enrichments: list[EnrichmentResult] = Field(default_factory=list)


class IncidentReport(BaseModel):
    source_file: str
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    context: IncidentContext = Field(default_factory=IncidentContext)
    artifacts: list[ArtifactReport] = Field(default_factory=list)

    @property
    def internal_ips(self) -> list[ArtifactReport]:
        return [
            a
            for a in self.artifacts
            if a.artifact.type == ArtifactType.IP
            and a.artifact.scope == ArtifactScope.INTERNAL
        ]

    @property
    def enrichable_artifacts(self) -> list[ArtifactReport]:
        enrichable = {
            ArtifactType.IP,
            ArtifactType.HASH_SHA256,
            ArtifactType.HASH_SHA1,
            ArtifactType.HASH_MD5,
            ArtifactType.DOMAIN,
            ArtifactType.URL,
        }
        return [
            a
            for a in self.artifacts
            if a.artifact.type in enrichable
            and a.artifact.scope == ArtifactScope.PUBLIC
        ]
