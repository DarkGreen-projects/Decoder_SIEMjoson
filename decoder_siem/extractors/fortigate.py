from __future__ import annotations

from typing import Any

from decoder_siem.extractors.generic import GenericExtractor, _make_artifact
from decoder_siem.extractors.patterns import is_private_ip
from decoder_siem.models import Artifact, ArtifactType

IP_KEYS = (
    "FTNTFGTsrcip",
    "src",
    "FTNTFGTdstip",
    "dst",
    "FTNTFGTtransip",
    "FTNTFGTlocip",
    "FTNTFGTremip",
)
HOSTNAME_KEYS = ("FTNTFGThostname", "shost", "dhost", "hostname")
URL_KEYS = ("FTNTFGTurl", "request", "url")
DOMAIN_KEYS = ("FTNTFGTdomain", "domain")


class FortiGateExtractor:
    """Estrae artefatti da log FortiGate in formato CEF parsato."""

    def __init__(self) -> None:
        self._generic = GenericExtractor()

    def extract(self, document: dict[str, Any]) -> list[Artifact]:
        artifacts: list[Artifact] = []
        base = "FortiGate"
        cef = document.get("cef") or {}
        syslog = document.get("syslog") or {}
        extension = cef.get("extension") or {}

        hostname = syslog.get("hostname")
        self._add_if_present(
            artifacts, ArtifactType.HOSTNAME, hostname, f"{base}.syslog.hostname"
        )

        for key in IP_KEYS:
            self._add_if_present(
                artifacts, ArtifactType.IP, extension.get(key), f"{base}.cef.extension.{key}"
            )

        for key in HOSTNAME_KEYS:
            val = extension.get(key)
            if val and not self._looks_like_ip(val):
                self._add_if_present(
                    artifacts,
                    ArtifactType.HOSTNAME,
                    val,
                    f"{base}.cef.extension.{key}",
                )
            elif val and self._looks_like_ip(val):
                self._add_if_present(
                    artifacts, ArtifactType.IP, val, f"{base}.cef.extension.{key}"
                )

        for key in URL_KEYS:
            self._add_if_present(
                artifacts, ArtifactType.URL, extension.get(key), f"{base}.cef.extension.{key}"
            )

        for key in DOMAIN_KEYS:
            val = extension.get(key)
            if val and not self._looks_like_ip(val):
                self._add_if_present(
                    artifacts,
                    ArtifactType.DOMAIN,
                    val,
                    f"{base}.cef.extension.{key}",
                )

        self._add_if_present(
            artifacts,
            ArtifactType.OTHER,
            extension.get("deviceExternalId"),
            f"{base}.cef.extension.deviceExternalId",
        )

        # Generic regex on extension values and CEF name
        artifacts.extend(self._generic.extract(extension, f"{base}.cef.extension"))
        artifacts.extend(self._generic.extract(cef, f"{base}.cef"))
        if syslog:
            artifacts.extend(self._generic.extract(syslog, f"{base}.syslog"))

        return artifacts

    def extract_context(self, document: dict[str, Any]) -> dict[str, Any]:
        cef = document.get("cef") or {}
        syslog = document.get("syslog") or {}
        extension = cef.get("extension") or {}

        severity = cef.get("severity")
        if isinstance(severity, str):
            try:
                severity = int(severity)
            except ValueError:
                pass

        return {
            "log_format": "cef",
            "incident_name": cef.get("name"),
            "event_name": cef.get("name"),
            "host_name": syslog.get("hostname"),
            "severity": severity if isinstance(severity, int) else None,
            "cef_severity": severity if isinstance(severity, int) else None,
            "log_description": extension.get("FTNTFGTlogdesc"),
            "message": extension.get("msg"),
            "device_external_id": extension.get("deviceExternalId"),
            "date_in": syslog.get("timestamp"),
            "extra": {
                "cat": extension.get("cat"),
                "FTNTFGTlevel": extension.get("FTNTFGTlevel"),
                "FTNTFGTsubtype": extension.get("FTNTFGTsubtype"),
                "signature_id": cef.get("signature_id"),
                "product": cef.get("product"),
            },
        }

    def _looks_like_ip(self, value: str) -> bool:
        try:
            import ipaddress

            ipaddress.ip_address(value.strip())
            return True
        except ValueError:
            return False

    def _add_if_present(
        self,
        artifacts: list[Artifact],
        artifact_type: ArtifactType,
        value: Any,
        provenance: str,
    ) -> None:
        if value is None:
            return
        text = str(value).strip()
        if not text:
            return
        if artifact_type == ArtifactType.IP and is_private_ip(text):
            artifacts.append(_make_artifact(artifact_type, text, provenance))
        elif artifact_type == ArtifactType.DOMAIN and (
            "." not in text or text.replace(".", "").isdigit()
        ):
            return
        else:
            artifacts.append(_make_artifact(artifact_type, text, provenance))
