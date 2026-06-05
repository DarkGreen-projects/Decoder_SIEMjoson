from __future__ import annotations

import html
from typing import Literal

from decoder_siem.enrichers.abuseipdb import AbuseIPDBEnricher
from decoder_siem.enrichers.otx import OTXEnricher
from decoder_siem.enrichers.urlhaus import URLhausEnricher
from decoder_siem.models import (
    Artifact,
    ArtifactReport,
    ArtifactScope,
    ArtifactType,
    EmailVerdict,
    EnrichmentResult,
    EnrichmentStatus,
    IncidentContext,
    IncidentReport,
)

TABLE_HEADERS = [
    "Tipo",
    "Valore",
    "Scope",
    "Provenienza",
    "VT Stato",
    "VT Riepilogo",
    "Link VT",
    "AbuseIPDB",
    "OTX",
    "URLhaus",
    "Link OSINT",
]

COLOR_BENIGN = "#2e7d32"
COLOR_MALICIOUS = "#960018"
COLOR_SPAM = "#e65100"
COLOR_NEUTRAL = "#616161"

HASH_TYPES = {
    ArtifactType.HASH_SHA256,
    ArtifactType.HASH_SHA1,
    ArtifactType.HASH_MD5,
}

LINKABLE_TYPES = HASH_TYPES | {
    ArtifactType.URL,
    ArtifactType.DOMAIN,
    ArtifactType.IP,
}

ENRICHABLE_TYPES = LINKABLE_TYPES

Verdict = Literal["malicious", "benign", "unknown"]


def enrichment_by_name(
    ar: ArtifactReport, name: str
) -> EnrichmentResult | None:
    for enr in ar.enrichments:
        if enr.enricher == name:
            return enr
    return None


def _vt_enrichment(ar: ArtifactReport) -> EnrichmentResult | None:
    return enrichment_by_name(ar, "virustotal")


def _vt_stats(ar: ArtifactReport) -> dict:
    enr = _vt_enrichment(ar)
    if not enr or not enr.data:
        return {}
    return enr.data.get("last_analysis_stats") or {}


def vt_permalink(ar: ArtifactReport) -> str | None:
    """URL pagina VirusTotal per hash, URL, dominio o IP pubblico."""
    art = ar.artifact
    enr = _vt_enrichment(ar)
    if enr and enr.data:
        link = enr.data.get("permalink")
        if link:
            return str(link)

    if art.type in HASH_TYPES:
        return f"https://www.virustotal.com/gui/file/{art.normalized_value}"

    if art.type == ArtifactType.URL:
        try:
            import vt

            url_id = vt.url_id(art.normalized_value)
            return f"https://www.virustotal.com/gui/url/{url_id}"
        except Exception:  # noqa: BLE001
            return None

    if art.type == ArtifactType.DOMAIN:
        return f"https://www.virustotal.com/gui/domain/{art.normalized_value}"

    if art.type == ArtifactType.IP and art.scope == ArtifactScope.PUBLIC:
        return f"https://www.virustotal.com/gui/ip-address/{art.normalized_value}"

    return None


def _osint_links(ar: ArtifactReport) -> list[str]:
    links: list[str] = []
    for name in ("abuseipdb", "otx", "urlhaus"):
        enr = enrichment_by_name(ar, name)
        if enr and enr.status == EnrichmentStatus.SUCCESS and enr.data:
            link = enr.data.get("permalink") or enr.data.get("urlhaus_reference")
            if link and link not in links:
                links.append(str(link))
    return links


def _enrichment_is_malicious(enr: EnrichmentResult) -> bool:
    if enr.status != EnrichmentStatus.SUCCESS or not enr.data:
        return False
    data = enr.data
    if enr.enricher == "virustotal":
        stats = data.get("last_analysis_stats") or {}
        return stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0
    if enr.enricher == "abuseipdb":
        return AbuseIPDBEnricher.is_malicious(data)
    if enr.enricher == "otx":
        return OTXEnricher.is_malicious(data)
    if enr.enricher == "urlhaus":
        return URLhausEnricher.is_malicious(data)
    return False


def _enrichment_is_clean_success(enr: EnrichmentResult) -> bool:
    if enr.status != EnrichmentStatus.SUCCESS:
        return False
    return not _enrichment_is_malicious(enr)


def classify_artifact(ar: ArtifactReport) -> Verdict:
    art = ar.artifact

    if art.scope == ArtifactScope.INTERNAL:
        return "benign"

    if not ar.enrichments:
        if art.type not in ENRICHABLE_TYPES:
            return "benign"
        return "unknown"

    for enr in ar.enrichments:
        if _enrichment_is_malicious(enr):
            return "malicious"

    has_success = any(
        _enrichment_is_clean_success(enr) for enr in ar.enrichments
    )
    has_skipped_or_not_found = any(
        enr.status in (EnrichmentStatus.SKIPPED, EnrichmentStatus.NOT_FOUND)
        for enr in ar.enrichments
    )

    if has_success:
        return "benign"
    if has_skipped_or_not_found and art.type in ENRICHABLE_TYPES:
        return "benign"
    if art.type not in ENRICHABLE_TYPES:
        return "benign"
    return "unknown"


def verdict_color(verdict: Verdict) -> str:
    return COLOR_MALICIOUS if verdict == "malicious" else COLOR_BENIGN


def _format_enrichment_snippet(enr: EnrichmentResult) -> str | None:
    if enr.status == EnrichmentStatus.SUCCESS and enr.data:
        data = enr.data
        if enr.enricher == "virustotal":
            ratio = data.get("detection_ratio")
            return f"VT {ratio}" if ratio else (enr.summary or "VT ok")
        if enr.enricher == "abuseipdb":
            score = data.get("abuse_confidence_score")
            return f"AbuseIPDB {score}%"
        if enr.enricher == "otx":
            pulses = data.get("pulse_count", 0)
            return f"OTX {pulses} pulse"
        if enr.enricher == "urlhaus":
            status = data.get("url_status")
            if status:
                return f"URLhaus {status}"
            url_count = data.get("url_count")
            if url_count:
                return f"URLhaus {url_count} URL"
            return enr.summary or "URLhaus ok"
    if enr.status == EnrichmentStatus.NOT_FOUND:
        labels = {
            "virustotal": "assente su VT",
            "abuseipdb": "assente su AbuseIPDB",
            "otx": "assente su OTX",
            "urlhaus": "assente su URLhaus",
        }
        return labels.get(enr.enricher, enr.summary)
    if enr.status == EnrichmentStatus.SKIPPED:
        return enr.summary
    if enr.status == EnrichmentStatus.ERROR:
        return enr.summary or f"errore {enr.enricher}"
    return None


def _artifact_note(ar: ArtifactReport) -> str:
    art = ar.artifact
    if art.scope == ArtifactScope.INTERNAL:
        return "interno"

    if not ar.enrichments:
        return "non verificato"

    parts: list[str] = []
    for name in ("virustotal", "abuseipdb", "otx", "urlhaus"):
        enr = enrichment_by_name(ar, name)
        if enr:
            snippet = _format_enrichment_snippet(enr)
            if snippet:
                parts.append(snippet)

    if parts:
        return " | ".join(parts)
    return "non verificato"


def _abuseipdb_cell(ar: ArtifactReport) -> str:
    enr = enrichment_by_name(ar, "abuseipdb")
    if not enr:
        return "-"
    if enr.status == EnrichmentStatus.SUCCESS and enr.data:
        score = enr.data.get("abuse_confidence_score")
        return f"{score}%" if score is not None else (enr.summary or "-")
    if enr.status == EnrichmentStatus.NOT_FOUND:
        return "non presente"
    return enr.summary or enr.status.value


def _otx_cell(ar: ArtifactReport) -> str:
    enr = enrichment_by_name(ar, "otx")
    if not enr:
        return "-"
    if enr.status == EnrichmentStatus.SUCCESS and enr.data:
        pulses = enr.data.get("pulse_count")
        return str(pulses) if pulses is not None else (enr.summary or "-")
    if enr.status == EnrichmentStatus.NOT_FOUND:
        return "non presente"
    return enr.summary or enr.status.value


def _urlhaus_cell(ar: ArtifactReport) -> str:
    enr = enrichment_by_name(ar, "urlhaus")
    if not enr:
        return "-"
    if enr.status == EnrichmentStatus.SUCCESS and enr.data:
        status = enr.data.get("url_status")
        if status:
            return str(status)
        url_count = enr.data.get("url_count")
        if url_count:
            return f"{url_count} URL"
        return "presente"
    if enr.status == EnrichmentStatus.NOT_FOUND:
        return "non presente"
    return enr.summary or enr.status.value


def _osint_link_cell(ar: ArtifactReport) -> str:
    links = _osint_links(ar)
    if not links:
        return "-"
    return links[0] if len(links) == 1 else "; ".join(links)


def _value_supports_vt_link(art: Artifact) -> bool:
    if art.type in HASH_TYPES or art.type == ArtifactType.URL:
        return True
    if art.type == ArtifactType.DOMAIN:
        return True
    if art.type == ArtifactType.IP and art.scope == ArtifactScope.PUBLIC:
        return True
    return False


def _format_value_html(ar: ArtifactReport) -> str:
    art = ar.artifact
    value_esc = html.escape(art.value)
    link = vt_permalink(ar)
    if link and _value_supports_vt_link(art):
        link_esc = html.escape(link)
        return (
            f'<a href="{link_esc}" target="_blank" '
            f'rel="noopener noreferrer">{value_esc}</a>'
        )
    return value_esc


def email_verdict_color(verdict: str, criticality: int) -> str:
    if verdict == EmailVerdict.PHISHING.value:
        return COLOR_MALICIOUS
    if verdict == EmailVerdict.SPAM.value:
        return COLOR_SPAM
    if criticality < 30:
        return COLOR_BENIGN
    return COLOR_NEUTRAL


def email_verdict_html(report: IncidentReport) -> str:
    extra = report.context.extra or {}
    analysis = extra.get("email_analysis")
    if not analysis:
        return ""

    verdict = analysis.get("verdict", "other")
    criticality = analysis.get("criticality", 0)
    confidence = analysis.get("confidence", "low")
    indicators = analysis.get("indicators") or []
    auth = analysis.get("auth") or {}
    color = email_verdict_color(verdict, criticality)

    verdict_label = {
        EmailVerdict.PHISHING.value: "PHISHING",
        EmailVerdict.SPAM.value: "SPAM",
        EmailVerdict.OTHER.value: "ALTRO",
    }.get(verdict, verdict.upper())

    auth_line = (
        f"SPF: {auth.get('spf', 'N/D')} | "
        f"DKIM: {auth.get('dkim', 'N/D')} | "
        f"DMARC: {auth.get('dmarc', 'N/D')}"
    )
    indicator_items = "".join(
        f"<li>{html.escape(ind)}</li>" for ind in indicators[:8]
    )
    more = ""
    if len(indicators) > 8:
        more = f"<li><i>+{len(indicators) - 8} altri indicatori</i></li>"

    return (
        f'<div class="email-verdict-panel" style="margin-bottom:1rem; padding:0.75rem; '
        f'border-left:4px solid {color}; background:#fafafa;">'
        f'<h4 style="margin:0 0 0.5rem 0; color:{color};">'
        f"Analisi email: {html.escape(verdict_label)} — "
        f"criticità {criticality}/100 ({html.escape(confidence)})"
        f"</h4>"
        f'<p style="margin:0.35rem 0;">{html.escape(auth_line)}</p>'
        f'<ul style="margin:0.35rem 0 0 1.2em; padding:0;">{indicator_items}{more}</ul>'
        f"</div>"
    )


def report_to_colored_html(report: IncidentReport) -> str:
    email_panel = email_verdict_html(report)
    display_artifacts = [
        ar
        for ar in report.artifacts
        if ar.artifact.provenance != ["email.analysis"]
    ]

    if not display_artifacts:
        body = "<p><i>Nessun IOC estratto dagli header.</i></p>"
        if not email_panel:
            return (
                '<div class="artifacts-panel">'
                "<h4>Elementi analizzati</h4>"
                f"{body}</div>"
            )
        return (
            '<div class="artifacts-panel">'
            f"{email_panel}"
            "<h4>Elementi analizzati</h4>"
            f"{body}</div>"
        )

    items: list[str] = []
    for ar in display_artifacts:
        verdict = classify_artifact(ar)
        color = verdict_color(verdict)
        art = ar.artifact
        note = _artifact_note(ar)
        suffix = " (non verificato)" if verdict == "unknown" else ""
        value_html = _format_value_html(ar)
        type_esc = html.escape(art.type.value)
        note_esc = html.escape(note + suffix)
        items.append(
            f'<li style="color:{color}; margin-bottom:0.35em;">'
            f"<b>{type_esc}</b>: {value_html} — <span>{note_esc}</span></li>"
        )

    legend = (
        f'<p style="font-size:0.85em; color:#555;">'
        f'<span style="color:{COLOR_BENIGN};">■</span> non malevolo &nbsp; '
        f'<span style="color:{COLOR_MALICIOUS};">■</span> malevolo (OSINT aggregato) &nbsp; '
        f"hash/URL cliccabili → VirusTotal"
        f"</p>"
    )
    return (
        '<div class="artifacts-panel">'
        f"{email_panel}"
        "<h4>Elementi analizzati</h4>"
        f"{legend}"
        f'<ul style="list-style:disc; padding-left:1.2em;">{"".join(items)}</ul>'
        "</div>"
    )


def report_to_rows(report: IncidentReport) -> list[list[str]]:
    rows: list[list[str]] = []
    for ar in report.artifacts:
        art = ar.artifact
        vt_enr = _vt_enrichment(ar)
        if vt_enr:
            vt_status = vt_enr.status.value
            vt_summary = vt_enr.summary or "-"
        else:
            vt_status = "-"
            vt_summary = "-"

        link = vt_permalink(ar)
        if link and _value_supports_vt_link(art):
            link_cell = link
        else:
            link_cell = "-"

        rows.append(
            [
                art.type.value,
                art.value,
                art.scope.value,
                "; ".join(art.provenance),
                vt_status,
                vt_summary,
                link_cell,
                _abuseipdb_cell(ar),
                _otx_cell(ar),
                _urlhaus_cell(ar),
                _osint_link_cell(ar),
            ]
        )
    return rows


def context_to_markdown(ctx: IncidentContext, *, artifact_count: int = 0) -> str:
    lines: list[str] = ["### Riepilogo incidente", ""]
    if ctx.vendor:
        lines.append(f"- **Vendor:** {ctx.vendor}")
    if ctx.log_format:
        lines.append(f"- **Formato:** {ctx.log_format}")
    if ctx.incident_name:
        lines.append(f"- **Titolo:** {ctx.incident_name}")
    if ctx.event_name:
        lines.append(f"- **Evento / Detector:** {ctx.event_name}")
    if ctx.host_name:
        lines.append(f"- **Host:** {ctx.host_name}")
    if ctx.host_ip:
        lines.append(f"- **IP host:** {ctx.host_ip}")
    if ctx.user_name:
        lines.append(f"- **Utente:** {ctx.user_name}")
    if ctx.severity is not None:
        lines.append(f"- **Severità (numerica):** {ctx.severity}")
    if ctx.device_external_id:
        lines.append(f"- **Device ID:** {ctx.device_external_id}")
    if ctx.malware_id:
        lines.append(f"- **Malware ID:** {ctx.malware_id}")
    if ctx.mail_from:
        lines.append(f"- **From:** {ctx.mail_from}")
    if ctx.reply_to:
        lines.append(f"- **Reply-To:** {ctx.reply_to}")
    if ctx.subject:
        lines.append(f"- **Subject:** {ctx.subject}")

    extra = ctx.extra or {}
    email_analysis = extra.get("email_analysis")
    if email_analysis:
        lines.append(
            f"- **Verdetto email:** {email_analysis.get('verdict', 'N/D')} "
            f"(criticità {email_analysis.get('criticality', 0)}/100)"
        )
        auth = email_analysis.get("auth") or {}
        lines.append(
            f"- **Auth:** SPF={auth.get('spf', 'N/D')}, "
            f"DKIM={auth.get('dkim', 'N/D')}, DMARC={auth.get('dmarc', 'N/D')}"
        )
    if extra.get("severity_text"):
        lines.append(f"- **Severità:** {extra['severity_text']}")
    if extra.get("mitre_techniques"):
        lines.append(
            f"- **MITRE ATT&CK:** {', '.join(extra['mitre_techniques'])}"
        )
    if extra.get("incident_id"):
        lines.append(f"- **Incident ID:** {extra['incident_id']}")

    lines.append(f"- **Artefatti estratti:** {artifact_count}")
    if len(lines) <= 3:
        lines.append("- Nessun contesto estratto.")
    return "\n".join(lines)
