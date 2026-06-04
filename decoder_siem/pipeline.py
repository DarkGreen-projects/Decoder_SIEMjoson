from __future__ import annotations

from pathlib import Path

from decoder_siem.enrichers.virustotal import VirusTotalEnricher
from decoder_siem.extractors import CynetExtractor, GenericExtractor, merge_artifacts
from decoder_siem.models import (
    ArtifactReport,
    EnrichmentResult,
    EnrichmentStatus,
    IncidentContext,
    IncidentReport,
)
from decoder_siem.parser import prepare_incident_data


def extract_artifacts_from_file(path: Path) -> tuple[list, IncidentContext]:
    parsed, vendor, block = prepare_incident_data(path)
    generic = GenericExtractor()
    artifacts = generic.extract(parsed, "root")

    context = IncidentContext(vendor=vendor)
    if vendor == "Cynet" and block:
        cynet = CynetExtractor()
        artifacts = merge_artifacts(cynet.extract(block), artifacts)
        ctx_data = cynet.extract_context(block)
        context = IncidentContext(
            vendor=vendor,
            incident_name=ctx_data.get("incident_name"),
            host_name=ctx_data.get("host_name"),
            host_ip=ctx_data.get("host_ip"),
            user_name=ctx_data.get("user_name"),
            severity=ctx_data.get("severity"),
            malware_id=ctx_data.get("malware_id"),
            malware_type=ctx_data.get("malware_type"),
            date_in=ctx_data.get("date_in"),
        )

    return artifacts, context


def build_report(
    path: Path,
    *,
    enrich: bool = True,
    api_key: str | None = None,
    requests_per_minute: int = 4,
    cache_dir: Path | None = None,
) -> IncidentReport:
    artifacts, context = extract_artifacts_from_file(path)
    artifact_reports = [ArtifactReport(artifact=a) for a in artifacts]

    report = IncidentReport(
        source_file=str(path),
        context=context,
        artifacts=artifact_reports,
    )

    if not enrich:
        return report

    if not api_key:
        for ar in report.enrichable_artifacts:
            ar.enrichments.append(
                EnrichmentResult(
                    enricher="virustotal",
                    status=EnrichmentStatus.SKIPPED,
                    summary="VT_API_KEY non configurata",
                )
            )
        return report

    enricher = VirusTotalEnricher(
        api_key,
        requests_per_minute=requests_per_minute,
        cache_dir=cache_dir,
    )
    try:
        for ar in report.enrichable_artifacts:
            if enricher.supports(ar.artifact):
                ar.enrichments.append(enricher.enrich(ar.artifact))
        for ar in report.internal_ips:
            ar.enrichments.append(
                EnrichmentResult(
                    enricher="virustotal",
                    status=EnrichmentStatus.SKIPPED,
                    summary="IP interno (RFC1918/link-local): correlare nel SIEM locale",
                )
            )
    finally:
        enricher.close()

    return report
