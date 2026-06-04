from __future__ import annotations

import html
from typing import Literal

from decoder_siem.models import (
    ArtifactReport,
    ArtifactScope,
    ArtifactType,
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
]

COLOR_BENIGN = "#2e7d32"
COLOR_MALICIOUS = "#960018"

ENRICHABLE_TYPES = {
    ArtifactType.IP,
    ArtifactType.HASH_SHA256,
    ArtifactType.HASH_SHA1,
    ArtifactType.HASH_MD5,
    ArtifactType.DOMAIN,
    ArtifactType.URL,
}

Verdict = Literal["malicious", "benign", "unknown"]


def _vt_stats(ar: ArtifactReport) -> dict:
    if not ar.enrichments:
        return {}
    data = ar.enrichments[0].data or {}
    return data.get("last_analysis_stats") or {}


def classify_artifact(ar: ArtifactReport) -> Verdict:
    art = ar.artifact

    if not ar.enrichments:
        if art.type not in ENRICHABLE_TYPES or art.scope == ArtifactScope.INTERNAL:
            return "benign"
        return "unknown"

    enr = ar.enrichments[0]

    if enr.status == EnrichmentStatus.SUCCESS:
        stats = _vt_stats(ar)
        if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
            return "malicious"
        return "benign"

    if enr.status in (EnrichmentStatus.SKIPPED, EnrichmentStatus.NOT_FOUND):
        return "benign"

    return "unknown"


def verdict_color(verdict: Verdict) -> str:
    return COLOR_MALICIOUS if verdict == "malicious" else COLOR_BENIGN


def _artifact_note(ar: ArtifactReport) -> str:
    art = ar.artifact
    if art.scope == ArtifactScope.INTERNAL:
        return "interno"

    if not ar.enrichments:
        return "non verificato"

    enr = ar.enrichments[0]
    if enr.status == EnrichmentStatus.SKIPPED:
        return enr.summary or "saltato"
    if enr.status == EnrichmentStatus.NOT_FOUND:
        return "assente su VT"
    if enr.status == EnrichmentStatus.ERROR:
        return enr.summary or "errore VT"
    if enr.status == EnrichmentStatus.SUCCESS:
        data = enr.data or {}
        ratio = data.get("detection_ratio")
        if ratio:
            return f"VT {ratio}"
        return enr.summary or "VT ok"

    return "non verificato"


def report_to_colored_html(report: IncidentReport) -> str:
    if not report.artifacts:
        return (
            '<div class="artifacts-panel">'
            "<h4>Elementi analizzati</h4>"
            "<p><i>Nessun artefatto estratto.</i></p></div>"
        )

    items: list[str] = []
    for ar in report.artifacts:
        verdict = classify_artifact(ar)
        color = verdict_color(verdict)
        art = ar.artifact
        note = _artifact_note(ar)
        suffix = " (non verificato)" if verdict == "unknown" else ""
        value_esc = html.escape(art.value)
        type_esc = html.escape(art.type.value)
        note_esc = html.escape(note + suffix)
        items.append(
            f'<li style="color:{color}; margin-bottom:0.35em;">'
            f"<b>{type_esc}</b>: {value_esc} — <span>{note_esc}</span></li>"
        )

    legend = (
        f'<p style="font-size:0.85em; color:#555;">'
        f'<span style="color:{COLOR_BENIGN};">■</span> non malevolo &nbsp; '
        f'<span style="color:{COLOR_MALICIOUS};">■</span> malevolo (VT)'
        f"</p>"
    )
    return (
        '<div class="artifacts-panel">'
        "<h4>Elementi analizzati</h4>"
        f"{legend}"
        f'<ul style="list-style:disc; padding-left:1.2em;">{"".join(items)}</ul>'
        "</div>"
    )


def report_to_rows(report: IncidentReport) -> list[list[str]]:
    rows: list[list[str]] = []
    for ar in report.artifacts:
        art = ar.artifact
        if ar.enrichments:
            enr = ar.enrichments[0]
            vt_status = enr.status.value
            vt_summary = enr.summary or "-"
        else:
            vt_status = "-"
            vt_summary = "-"
        rows.append(
            [
                art.type.value,
                art.value,
                art.scope.value,
                "; ".join(art.provenance),
                vt_status,
                vt_summary,
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

    extra = ctx.extra or {}
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
