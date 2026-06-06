from __future__ import annotations

from typing import Any

from decoder_siem.analyzers.email_scorer import score_email
from decoder_siem.extractors.generic import GenericExtractor
from decoder_siem.extractors.patterns import is_private_ip, normalize_domain, normalize_hash, normalize_ip
from decoder_siem.models import Artifact, ArtifactScope, ArtifactType
from decoder_siem.parsers.email import ParsedEmail, parsed_email_from_dict

MAX_BODY_IOCS = 15
MAX_BODY_IOCS_FULL_MIME = 30
_BODY_IOC_TYPES = {
    ArtifactType.IP,
    ArtifactType.DOMAIN,
    ArtifactType.URL,
    ArtifactType.HASH_SHA256,
    ArtifactType.HASH_SHA1,
    ArtifactType.HASH_MD5,
}


class EmailHeaderExtractor:
    def extract(self, block: dict[str, Any]) -> list[Artifact]:
        parsed = parsed_email_from_dict(block)
        artifacts: list[Artifact] = []

        def add_email(addr_data: dict[str, Any] | None, role: str) -> None:
            if not addr_data or not addr_data.get("email"):
                return
            email = addr_data["email"]
            artifacts.append(
                Artifact(
                    type=ArtifactType.EMAIL_ADDRESS,
                    value=email,
                    normalized_value=email.lower(),
                    provenance=[f"email.header.{role}"],
                    context={"role": role, "display_name": addr_data.get("display_name")},
                )
            )
            domain = addr_data.get("domain")
            if domain:
                artifacts.append(
                    Artifact(
                        type=ArtifactType.DOMAIN,
                        value=domain,
                        normalized_value=normalize_domain(domain),
                        provenance=[f"email.header.{role}.domain"],
                        context={"role": role},
                    )
                )

        add_email(block.get("from_addr"), "from")
        add_email(block.get("reply_to"), "reply_to")
        add_email(block.get("return_path"), "return_path")
        add_email(block.get("sender"), "sender")

        seen_ips: set[str] = set()
        for hop in parsed.received_hops:
            if hop.ip and hop.ip not in seen_ips:
                seen_ips.add(hop.ip)
                norm = normalize_ip(hop.ip)
                scope = (
                    ArtifactScope.INTERNAL
                    if is_private_ip(norm)
                    else ArtifactScope.PUBLIC
                )
                artifacts.append(
                    Artifact(
                        type=ArtifactType.IP,
                        value=hop.ip,
                        normalized_value=norm,
                        scope=scope,
                        provenance=["email.received"],
                        context={"hop": hop.raw[:120]},
                    )
                )

        body_parts: list[str] = []
        if parsed.body_text:
            body_parts.append(parsed.body_text)
        if parsed.body_html:
            body_parts.append(parsed.body_html)
        combined_body = "\n".join(body_parts).strip()
        if combined_body:
            generic = GenericExtractor()
            body_arts = generic.extract({"body": combined_body}, "email.body")
            body_iocs = [a for a in body_arts if a.type in _BODY_IOC_TYPES]
            cap = (
                MAX_BODY_IOCS_FULL_MIME
                if parsed.content_profile == "full_mime"
                else MAX_BODY_IOCS
            )
            artifacts.extend(body_iocs[:cap])

        seen_urls: set[str] = set()
        for link in parsed.body_links:
            href = link.href.strip()
            if not href or href in seen_urls:
                continue
            if not href.lower().startswith(("http://", "https://")):
                continue
            seen_urls.add(href)
            artifacts.append(
                Artifact(
                    type=ArtifactType.URL,
                    value=href,
                    normalized_value=href,
                    provenance=["email.body.link"],
                    context={"display_text": link.display_text[:80]},
                )
            )

        seen_hashes: set[str] = set()
        for att in parsed.attachments:
            if not att.sha256 or att.sha256 in seen_hashes:
                continue
            seen_hashes.add(att.sha256)
            artifacts.append(
                Artifact(
                    type=ArtifactType.HASH_SHA256,
                    value=att.sha256,
                    normalized_value=normalize_hash(att.sha256),
                    provenance=[f"email.attachment.{att.filename}"],
                    context={
                        "filename": att.filename,
                        "content_type": att.content_type,
                        "size_bytes": att.size_bytes,
                    },
                )
            )

        return artifacts

    def extract_context(self, block: dict[str, Any]) -> dict[str, Any]:
        parsed = parsed_email_from_dict(block)
        analysis = score_email(parsed)
        from_addr = block.get("from_addr") or {}
        reply_to = block.get("reply_to") or {}
        return {
            "vendor": "EmailHeaders",
            "log_format": "email",
            "incident_name": analysis.summary,
            "event_name": analysis.verdict.value,
            "mail_from": from_addr.get("raw") or from_addr.get("email"),
            "reply_to": reply_to.get("raw") or reply_to.get("email"),
            "subject": block.get("subject"),
            "message": analysis.summary,
            "extra": {
                "email_analysis": analysis.model_dump(),
                "hop_count": len(parsed.received_hops),
                "auth": analysis.auth,
                "content_profile": parsed.content_profile,
                "attachments_count": len(parsed.attachments),
            },
        }
