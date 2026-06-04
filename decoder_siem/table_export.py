from __future__ import annotations

from decoder_siem.models import IncidentContext, IncidentReport

TABLE_HEADERS = [
    "Tipo",
    "Valore",
    "Scope",
    "Provenienza",
    "VT Stato",
    "VT Riepilogo",
]


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
