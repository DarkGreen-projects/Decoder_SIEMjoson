from __future__ import annotations

from typing import Any

from decoder_siem.extractors.generic import GenericExtractor, _make_artifact
from decoder_siem.extractors.patterns import (
    HOST_IP_RE,
    HOSTNAME_RE,
    MALWARE_ID_RE,
    PROCESS_SHA256_RE,
)
from decoder_siem.models import Artifact, ArtifactType

_EXTRA_INFO_FIELD_META: dict[str, tuple[str, str]] = {
    "Created File Sha256": ("infected", "infected_file"),
    "Infected file SHA256": ("infected", "infected_file"),
    "Created File Path": ("infected", "infected_file"),
    "Infected file": ("infected", "infected_file"),
    "Sha256": ("process_extra", "parent_process"),
    "Parent SHA256": ("parent", "parent_process"),
    "Parent Path": ("parent", "parent_process"),
    "Path": ("infected", "infected_file"),
}


class CynetExtractor:
    """Estrae artefatti dai campi noti del formato Cynet."""

    def __init__(self) -> None:
        self._generic = GenericExtractor()

    def extract(self, cynet_block: dict[str, Any]) -> list[Artifact]:
        artifacts: list[Artifact] = []
        base = "Cynet"
        primary_group = f"{base}.primary_file"

        self._add_if_present(
            artifacts,
            ArtifactType.IP,
            cynet_block.get("HostIp"),
            f"{base}.HostIp",
        )
        self._add_if_present(
            artifacts,
            ArtifactType.HASH_SHA256,
            cynet_block.get("Sha256Hex"),
            f"{base}.Sha256Hex",
            correlation_group=primary_group,
            entity_role="infected_file",
        )
        self._add_if_present(
            artifacts,
            ArtifactType.FILE_PATH,
            cynet_block.get("Path"),
            f"{base}.Path",
            correlation_group=primary_group,
            entity_role="infected_file",
        )
        self._add_if_present(
            artifacts,
            ArtifactType.HOSTNAME,
            cynet_block.get("HostName"),
            f"{base}.HostName",
        )
        self._add_if_present(
            artifacts,
            ArtifactType.USERNAME,
            cynet_block.get("UserName"),
            f"{base}.UserName",
        )
        self._add_if_present(
            artifacts,
            ArtifactType.DOMAIN,
            cynet_block.get("AlertDomain"),
            f"{base}.AlertDomain",
            entity_role="network",
        )
        self._add_if_present(
            artifacts,
            ArtifactType.URL,
            cynet_block.get("AlertUrl"),
            f"{base}.AlertUrl",
            correlation_group=primary_group,
            entity_role="download_url",
        )

        desc = cynet_block.get("IncidentDescription")
        if isinstance(desc, str):
            artifacts.extend(self._from_incident_description(desc))

        nested = cynet_block.get("IncidentJsonDescription")
        if isinstance(nested, dict):
            artifacts.extend(self._from_incident_json(nested, f"{base}.IncidentJsonDescription"))
        elif isinstance(nested, str):
            artifacts.extend(self._generic.extract(nested, f"{base}.IncidentJsonDescription"))

        for section_key in (
            "Parent Process Details",
            "Grandparent Process Details",
        ):
            section = cynet_block.get(section_key)
            if isinstance(section, dict):
                artifacts.extend(
                    self._from_process_section(section, f"{base}.{section_key}")
                )

        return artifacts

    def extract_context(self, cynet_block: dict[str, Any]) -> dict[str, Any]:
        ctx: dict[str, Any] = {
            "incident_name": cynet_block.get("IncidentName"),
            "host_name": cynet_block.get("HostName"),
            "host_ip": cynet_block.get("HostIp"),
            "user_name": cynet_block.get("UserName"),
            "severity": cynet_block.get("Severity"),
            "date_in": cynet_block.get("DateIn"),
        }
        nested = cynet_block.get("IncidentJsonDescription")
        if isinstance(nested, dict):
            extra = nested.get("Extra Info")
            if isinstance(extra, dict):
                ctx["malware_id"] = extra.get("Malware ID")
                ctx["malware_type"] = extra.get("Malware Type")
            if not ctx.get("malware_id"):
                ctx["malware_id"] = nested.get("Malware ID")
            if not ctx.get("malware_type"):
                ctx["malware_type"] = nested.get("Malware Type")
        return ctx

    def _from_incident_description(self, text: str) -> list[Artifact]:
        found: list[Artifact] = []
        path = "Cynet.IncidentDescription"

        for match in HOST_IP_RE.finditer(text):
            found.append(
                _make_artifact(ArtifactType.IP, match.group(1), path)
            )
        for match in HOSTNAME_RE.finditer(text):
            found.append(
                _make_artifact(ArtifactType.HOSTNAME, match.group(1).strip(), path)
            )
        for match in PROCESS_SHA256_RE.finditer(text):
            found.append(
                _make_artifact(
                    ArtifactType.HASH_SHA256, match.group(1), path
                )
            )
        for match in MALWARE_ID_RE.finditer(text):
            found.append(
                _make_artifact(
                    ArtifactType.MALWARE_LABEL, match.group(1).strip(), path
                )
            )

        found.extend(self._generic.extract(text, path))
        return found

    def _from_incident_json(
        self, data: dict[str, Any], base_path: str
    ) -> list[Artifact]:
        artifacts: list[Artifact] = []

        host_ip = data.get("Host Ip") or data.get("Host IP")
        self._add_if_present(
            artifacts, ArtifactType.IP, host_ip, f"{base_path}.Host Ip"
        )

        extra = data.get("Extra Info")
        if isinstance(extra, dict):
            artifacts.extend(self._from_extra_info(extra, f"{base_path}.Extra Info"))

        for section_key in (
            "Parent Process Details",
            "Grandparent Process Details",
        ):
            section = data.get(section_key)
            if isinstance(section, dict):
                artifacts.extend(
                    self._from_process_section(section, f"{base_path}.{section_key}")
                )

        artifacts.extend(self._generic.extract(data, base_path))
        return artifacts

    def _from_extra_info(self, extra: dict[str, Any], base_path: str) -> list[Artifact]:
        artifacts: list[Artifact] = []
        for field, (group_suffix, role) in _EXTRA_INFO_FIELD_META.items():
            art_type = ArtifactType.HASH_SHA256
            if field in ("Created File Path", "Infected file", "Parent Path", "Path"):
                art_type = ArtifactType.FILE_PATH
            elif field in ("Malware ID", "Malware Type"):
                art_type = ArtifactType.MALWARE_LABEL
            if field in ("Malware ID", "Malware Type"):
                self._add_if_present(
                    artifacts,
                    art_type,
                    extra.get(field),
                    f"{base_path}.{field}",
                )
                continue
            self._add_if_present(
                artifacts,
                art_type,
                extra.get(field),
                f"{base_path}.{field}",
                correlation_group=f"{base_path}.{group_suffix}",
                entity_role=role,
            )
        for field in ("Malware ID", "Malware Type"):
            self._add_if_present(
                artifacts,
                ArtifactType.MALWARE_LABEL,
                extra.get(field),
                f"{base_path}.{field}",
            )
        artifacts.extend(self._generic.extract(extra, base_path))
        return artifacts

    def _from_process_section(
        self, section: dict[str, Any], base_path: str
    ) -> list[Artifact]:
        if "Grandparent" in base_path:
            role = "grandparent_process"
        else:
            role = "parent_process"

        artifacts: list[Artifact] = []
        self._add_if_present(
            artifacts,
            ArtifactType.HASH_SHA256,
            section.get("Process SHA256"),
            f"{base_path}.Process SHA256",
            correlation_group=base_path,
            entity_role=role,
        )
        self._add_if_present(
            artifacts,
            ArtifactType.FILE_PATH,
            section.get("Process Path"),
            f"{base_path}.Process Path",
            correlation_group=base_path,
            entity_role=role,
        )
        self._add_if_present(
            artifacts,
            ArtifactType.USERNAME,
            section.get("Process Running User"),
            f"{base_path}.Process Running User",
        )
        return artifacts

    def _add_if_present(
        self,
        artifacts: list[Artifact],
        artifact_type: ArtifactType,
        value: Any,
        provenance: str,
        *,
        correlation_group: str | None = None,
        entity_role: str | None = None,
    ) -> None:
        if value is None:
            return
        text = str(value).strip()
        if not text or text.lower() in ("null", "none", "0"):
            if artifact_type not in (ArtifactType.IP,):
                return
        if artifact_type == ArtifactType.IP and text == "0":
            return
        context: dict[str, Any] = {}
        if correlation_group:
            context["correlation_group"] = correlation_group
        if entity_role:
            context["entity_role"] = entity_role
        artifacts.append(
            _make_artifact(
                artifact_type,
                text,
                provenance,
                context=context or None,
            )
        )
