from __future__ import annotations

from pathlib import Path

from decoder_siem.enrichers.virustotal import VirusTotalEnricher
from decoder_siem.extractors import (
    CynetExtractor,
    FortiGateExtractor,
    GenericExtractor,
    merge_artifacts,
)
from decoder_siem.models import (
    ArtifactReport,
    EnrichmentResult,
    EnrichmentStatus,
    IncidentContext,
    IncidentReport,
)
from decoder_siem.parsers.loader import load_document


def _context_from_cynet(ctx_data: dict) -> IncidentContext:
    return IncidentContext(
        vendor="Cynet",
        log_format="json",
        incident_name=ctx_data.get("incident_name"),
        host_name=ctx_data.get("host_name"),
        host_ip=ctx_data.get("host_ip"),
        user_name=ctx_data.get("user_name"),
        severity=ctx_data.get("severity"),
        malware_id=ctx_data.get("malware_id"),
        malware_type=ctx_data.get("malware_type"),
        date_in=ctx_data.get("date_in"),
    )


def _context_from_fortigate(ctx_data: dict) -> IncidentContext:
    data = dict(ctx_data)
    extra = data.pop("extra", {}) or {}
    return IncidentContext(
        vendor="FortiGate",
        log_format=data.get("log_format", "cef"),
        incident_name=data.get("incident_name"),
        event_name=data.get("event_name"),
        host_name=data.get("host_name"),
        severity=data.get("severity"),
        cef_severity=data.get("cef_severity"),
        log_description=data.get("log_description"),
        message=data.get("message"),
        device_external_id=data.get("device_external_id"),
        date_in=data.get("date_in"),
        extra=extra,
    )


def extract_artifacts_from_file(path: Path) -> tuple[list, IncidentContext, dict | None]:
    doc = load_document(path)
    generic = GenericExtractor()
    artifacts = generic.extract(doc.data, "root")

    context = IncidentContext(vendor=doc.vendor, log_format=doc.format)

    if doc.vendor == "Cynet" and doc.vendor_block:
        cynet = CynetExtractor()
        artifacts = merge_artifacts(cynet.extract(doc.vendor_block), artifacts)
        context = _context_from_cynet(cynet.extract_context(doc.vendor_block))

    elif doc.vendor == "FortiGate" and doc.vendor_block:
        fg = FortiGateExtractor()
        artifacts = merge_artifacts(fg.extract(doc.vendor_block), artifacts)
        ctx_data = fg.extract_context(doc.vendor_block)
        context = _context_from_fortigate(ctx_data)

    return artifacts, context, doc.raw_event


def build_report(
    path: Path,
    *,
    enrich: bool = True,
    api_key: str | None = None,
    requests_per_minute: int = 4,
    cache_dir: Path | None = None,
) -> IncidentReport:
    artifacts, context, raw_event = extract_artifacts_from_file(path)
    artifact_reports = [ArtifactReport(artifact=a) for a in artifacts]

    report = IncidentReport(
        source_file=str(path),
        context=context,
        raw_event=raw_event,
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
