from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from decoder_siem.enrichment_config import EnrichmentConfig
from decoder_siem.enrichers.abuseipdb import AbuseIPDBEnricher
from decoder_siem.enrichers.otx import OTXEnricher
from decoder_siem.enrichers.urlhaus import URLhausEnricher
from decoder_siem.enrichers.virustotal import VirusTotalEnricher

if TYPE_CHECKING:
    from decoder_siem.enrichers.base import Enricher
from decoder_siem.extractors import (
    CynetExtractor,
    FortiGateExtractor,
    GenericExtractor,
    MicrosoftDefenderExtractor,
    merge_artifacts,
)
from decoder_siem.models import (
    Artifact,
    ArtifactReport,
    ArtifactScope,
    ArtifactType,
    EnrichmentResult,
    EnrichmentStatus,
    IncidentContext,
    IncidentReport,
)
from decoder_siem.parsers.loader import LoadedDocument, load_document, load_text


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


def _context_from_defender(ctx_data: dict) -> IncidentContext:
    data = dict(ctx_data)
    extra = data.pop("extra", {}) or {}
    return IncidentContext(
        vendor="MicrosoftDefender",
        log_format=data.get("log_format", "json"),
        incident_name=data.get("incident_name"),
        event_name=data.get("event_name"),
        host_name=data.get("host_name"),
        host_ip=data.get("host_ip"),
        severity=data.get("severity"),
        log_description=data.get("log_description"),
        message=data.get("message"),
        date_in=data.get("date_in"),
        extra=extra,
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


def _extract_from_document(
    doc: LoadedDocument,
) -> tuple[list, IncidentContext, dict | None]:
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

    elif doc.vendor == "MicrosoftDefender" and doc.vendor_block:
        md = MicrosoftDefenderExtractor()
        artifacts = merge_artifacts(md.extract(doc.vendor_block), artifacts)
        ctx_data = md.extract_context(doc.vendor_block)
        context = _context_from_defender(ctx_data)

    return artifacts, context, doc.raw_event


def extract_artifacts_from_text(text: str) -> tuple[list, IncidentContext, dict | None]:
    doc = load_text(text)
    return _extract_from_document(doc)


def extract_artifacts_from_file(path: Path) -> tuple[list, IncidentContext, dict | None]:
    doc = load_document(path)
    return _extract_from_document(doc)


def _build_enricher_chain(
    config: EnrichmentConfig,
    cache_dir: Path | None,
) -> list[Enricher]:
    rpm = config.osint_requests_per_minute
    chain: list[Enricher] = []

    if config.urlhaus_auth_key:
        chain.append(
            URLhausEnricher(
                config.urlhaus_auth_key,
                requests_per_minute=rpm,
                cache_dir=cache_dir,
            )
        )
    if config.abuseipdb_api_key:
        chain.append(
            AbuseIPDBEnricher(
                config.abuseipdb_api_key,
                max_age_in_days=config.abuseipdb_max_age_days,
                requests_per_minute=rpm,
                cache_dir=cache_dir,
            )
        )
    if config.otx_api_key:
        chain.append(
            OTXEnricher(
                config.otx_api_key,
                requests_per_minute=rpm,
                cache_dir=cache_dir,
            )
        )
    if config.vt_api_key:
        chain.append(
            VirusTotalEnricher(
                config.vt_api_key,
                requests_per_minute=config.vt_requests_per_minute,
                cache_dir=cache_dir,
            )
        )
    return chain


def _skipped_result(enricher: str, summary: str) -> EnrichmentResult:
    return EnrichmentResult(
        enricher=enricher,
        status=EnrichmentStatus.SKIPPED,
        summary=summary,
    )


def _apply_enrichment(
    report: IncidentReport,
    *,
    enrich: bool,
    config: EnrichmentConfig | None = None,
    api_key: str | None = None,
    requests_per_minute: int | None = None,
    cache_dir: Path | None = None,
) -> IncidentReport:
    if not enrich:
        return report

    if config is None:
        config = EnrichmentConfig.from_env()
        if api_key is not None:
            config = EnrichmentConfig(
                vt_api_key=api_key,
                abuseipdb_api_key=config.abuseipdb_api_key,
                otx_api_key=config.otx_api_key,
                urlhaus_auth_key=config.urlhaus_auth_key,
                vt_requests_per_minute=(
                    requests_per_minute
                    if requests_per_minute is not None
                    else config.vt_requests_per_minute
                ),
                osint_requests_per_minute=config.osint_requests_per_minute,
                abuseipdb_max_age_days=config.abuseipdb_max_age_days,
            )
        elif requests_per_minute is not None:
            config = EnrichmentConfig(
                vt_api_key=config.vt_api_key,
                abuseipdb_api_key=config.abuseipdb_api_key,
                otx_api_key=config.otx_api_key,
                urlhaus_auth_key=config.urlhaus_auth_key,
                vt_requests_per_minute=requests_per_minute,
                osint_requests_per_minute=config.osint_requests_per_minute,
                abuseipdb_max_age_days=config.abuseipdb_max_age_days,
            )

    enrichers = _build_enricher_chain(config, cache_dir)
    vt_in_chain = any(e.name == "virustotal" for e in enrichers)

    closable: list[VirusTotalEnricher] = [
        e for e in enrichers if isinstance(e, VirusTotalEnricher)
    ]
    try:
        for ar in report.enrichable_artifacts:
            for enricher in enrichers:
                if enricher.supports(ar.artifact):
                    ar.enrichments.append(enricher.enrich(ar.artifact))

            if not vt_in_chain and _artifact_supports_vt(ar.artifact):
                ar.enrichments.append(
                    _skipped_result(
                        "virustotal",
                        "VT_API_KEY non configurata",
                    )
                )

        for ar in report.internal_ips:
            if not vt_in_chain:
                ar.enrichments.append(
                    _skipped_result(
                        "virustotal",
                        "IP interno (RFC1918/link-local): correlare nel SIEM locale",
                    )
                )
    finally:
        for enricher in closable:
            enricher.close()

    return report


def _artifact_supports_vt(artifact: Artifact) -> bool:
    if artifact.scope == ArtifactScope.INTERNAL:
        return False
    return artifact.type in (
        ArtifactType.IP,
        ArtifactType.HASH_SHA256,
        ArtifactType.HASH_SHA1,
        ArtifactType.HASH_MD5,
        ArtifactType.DOMAIN,
        ArtifactType.URL,
    )


def build_report_from_text(
    text: str,
    *,
    enrich: bool = True,
    config: EnrichmentConfig | None = None,
    api_key: str | None = None,
    requests_per_minute: int = 4,
    cache_dir: Path | None = None,
) -> IncidentReport:
    artifacts, context, raw_event = extract_artifacts_from_text(text)
    artifact_reports = [ArtifactReport(artifact=a) for a in artifacts]

    report = IncidentReport(
        source_file="(input)",
        context=context,
        raw_event=raw_event,
        artifacts=artifact_reports,
    )
    return _apply_enrichment(
        report,
        enrich=enrich,
        config=config,
        api_key=api_key,
        requests_per_minute=requests_per_minute,
        cache_dir=cache_dir,
    )


def build_report(
    path: Path,
    *,
    enrich: bool = True,
    config: EnrichmentConfig | None = None,
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
    return _apply_enrichment(
        report,
        enrich=enrich,
        config=config,
        api_key=api_key,
        requests_per_minute=requests_per_minute,
        cache_dir=cache_dir,
    )
