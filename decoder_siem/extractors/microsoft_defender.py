from __future__ import annotations

import re
from typing import Any
from decoder_siem.extractors.generic import GenericExtractor, _make_artifact
from decoder_siem.extractors.patterns import IPV4_RE, is_private_ip
from decoder_siem.models import Artifact, ArtifactType

IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")
SEVERITY_MAP = {"informational": 1, "low": 2, "medium": 3, "high": 4, "unknown": 0}


def _is_ip(value: str) -> bool:
    text = value.strip()
    if IPV4_RE.fullmatch(text):
        return True
    try:
        import ipaddress

        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _is_fqdn(value: str) -> bool:
    text = value.strip()
    if _is_ip(text) or not text or " " in text:
        return False
    return "." in text and not text.replace(".", "").isdigit()


class MicrosoftDefenderExtractor:
    """Estrae artefatti da alert Microsoft Graph / Defender."""

    def __init__(self) -> None:
        self._generic = GenericExtractor()

    def extract(self, alert: dict[str, Any]) -> list[Artifact]:
        artifacts: list[Artifact] = []
        base = "MicrosoftGraph"

        self._add_if_present(
            artifacts, ArtifactType.URL, alert.get("alertWebUrl"), f"{base}.alertWebUrl"
        )
        self._add_if_present(
            artifacts,
            ArtifactType.URL,
            alert.get("incidentWebUrl"),
            f"{base}.incidentWebUrl",
        )

        desc = alert.get("description")
        if isinstance(desc, str):
            artifacts.extend(self._generic.extract(desc, f"{base}.description"))

        evidence = alert.get("evidence")
        if isinstance(evidence, list):
            for idx, item in enumerate(evidence):
                if isinstance(item, dict):
                    artifacts.extend(
                        self._from_evidence(item, f"{base}.evidence[{idx}]")
                    )

        self._add_if_present(
            artifacts,
            ArtifactType.OTHER,
            alert.get("id"),
            f"{base}.id",
        )
        self._add_if_present(
            artifacts,
            ArtifactType.OTHER,
            alert.get("tenantId"),
            f"{base}.tenantId",
        )

        return artifacts

    def extract_context(self, alert: dict[str, Any]) -> dict[str, Any]:
        severity_raw = alert.get("severity")
        severity_int = None
        if isinstance(severity_raw, str):
            severity_int = SEVERITY_MAP.get(severity_raw.lower())

        host_ip = None
        host_name = None
        evidence = alert.get("evidence") or []
        for item in evidence:
            if not isinstance(item, dict):
                continue
            odata = item.get("@odata.type", "")
            roles = item.get("roles") or []
            if "deviceEvidence" in odata and "destination" in roles:
                host_name = item.get("hostName") or host_name
                host_ip = item.get("lastIpAddress") or host_ip
            if "deviceEvidence" in odata and "source" in roles:
                src = item.get("deviceDnsName") or item.get("lastIpAddress")
                if src and _is_ip(str(src)):
                    host_ip = host_ip or str(src)

        return {
            "log_format": "json",
            "incident_name": alert.get("title"),
            "event_name": alert.get("detectorId"),
            "host_name": host_name,
            "host_ip": host_ip,
            "severity": severity_int,
            "date_in": alert.get("createdDateTime"),
            "log_description": alert.get("description"),
            "message": alert.get("category"),
            "extra": {
                "severity_text": severity_raw,
                "incident_id": alert.get("incidentId"),
                "status": alert.get("status"),
                "product_name": alert.get("productName"),
                "service_source": alert.get("serviceSource"),
                "detection_source": alert.get("detectionSource"),
                "mitre_techniques": alert.get("mitreTechniques") or [],
                "categories": alert.get("categories") or [],
                "tenant_id": alert.get("tenantId"),
                "provider_alert_id": alert.get("providerAlertId"),
            },
        }

    def _from_evidence(self, item: dict[str, Any], base_path: str) -> list[Artifact]:
        artifacts: list[Artifact] = []
        odata = item.get("@odata.type", "")

        if "ipEvidence" in odata:
            self._add_ip(
                artifacts, item.get("ipAddress"), f"{base_path}.ipAddress"
            )

        elif "deviceEvidence" in odata:
            dns_name = item.get("deviceDnsName")
            if dns_name:
                if _is_ip(str(dns_name)):
                    self._add_ip(artifacts, str(dns_name), f"{base_path}.deviceDnsName")
                elif _is_fqdn(str(dns_name)):
                    self._add_if_present(
                        artifacts,
                        ArtifactType.DOMAIN,
                        str(dns_name),
                        f"{base_path}.deviceDnsName",
                    )
                    host = str(dns_name).split(".")[0]
                    self._add_if_present(
                        artifacts,
                        ArtifactType.HOSTNAME,
                        host,
                        f"{base_path}.deviceDnsName.host",
                    )

            self._add_if_present(
                artifacts,
                ArtifactType.HOSTNAME,
                item.get("hostName"),
                f"{base_path}.hostName",
            )
            self._add_ip(
                artifacts, item.get("lastIpAddress"), f"{base_path}.lastIpAddress"
            )
            self._add_ip(
                artifacts,
                item.get("lastExternalIpAddress"),
                f"{base_path}.lastExternalIpAddress",
            )
            self._add_if_present(
                artifacts,
                ArtifactType.DOMAIN,
                item.get("dnsDomain"),
                f"{base_path}.dnsDomain",
            )
            self._add_if_present(
                artifacts,
                ArtifactType.OTHER,
                item.get("mdeDeviceId"),
                f"{base_path}.mdeDeviceId",
            )

        elif "securityGroupEvidence" in odata:
            name = item.get("friendlyName") or item.get("displayName")
            self._add_if_present(
                artifacts,
                ArtifactType.USERNAME,
                name,
                f"{base_path}.friendlyName",
                context={"evidence_type": "security_group"},
            )
            self._add_if_present(
                artifacts,
                ArtifactType.OTHER,
                item.get("securityGroupId"),
                f"{base_path}.securityGroupId",
            )

        elif "userEvidence" in odata:
            self._add_if_present(
                artifacts,
                ArtifactType.USERNAME,
                item.get("userPrincipalName") or item.get("accountName"),
                f"{base_path}.user",
            )

        elif "urlEvidence" in odata:
            self._add_if_present(
                artifacts, ArtifactType.URL, item.get("url"), f"{base_path}.url"
            )

        elif "fileEvidence" in odata:
            self._add_if_present(
                artifacts,
                ArtifactType.HASH_SHA256,
                item.get("sha256"),
                f"{base_path}.sha256",
            )
            self._add_if_present(
                artifacts,
                ArtifactType.FILE_PATH,
                item.get("filePath"),
                f"{base_path}.filePath",
            )

        elif "processEvidence" in odata:
            self._add_if_present(
                artifacts,
                ArtifactType.HASH_SHA256,
                item.get("sha256"),
                f"{base_path}.process.sha256",
            )

        return artifacts

    def _add_ip(
        self,
        artifacts: list[Artifact],
        value: Any,
        provenance: str,
    ) -> None:
        if value is None:
            return
        text = str(value).strip()
        if not text:
            return
        if text == "::1" or is_private_ip(text):
            artifacts.append(_make_artifact(ArtifactType.IP, text, provenance))
        else:
            artifacts.append(_make_artifact(ArtifactType.IP, text, provenance))

    def _add_if_present(
        self,
        artifacts: list[Artifact],
        artifact_type: ArtifactType,
        value: Any,
        provenance: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> None:
        if value is None:
            return
        text = str(value).strip()
        if not text:
            return
        art = _make_artifact(artifact_type, text, provenance)
        if context:
            art.context.update(context)
        artifacts.append(art)
