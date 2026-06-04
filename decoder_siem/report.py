from __future__ import annotations

import json
from pathlib import Path

from decoder_siem.models import ArtifactScope, ArtifactType, IncidentReport


def write_json_report(report: IncidentReport, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        report.model_dump_json(indent=2),
        encoding="utf-8",
    )


def render_markdown(report: IncidentReport) -> str:
    lines: list[str] = []
    lines.append("# Report analisi incidente SIEM")
    lines.append("")
    lines.append(f"- **File sorgente:** `{report.source_file}`")
    lines.append(f"- **Generato:** {report.generated_at}")
    if report.context.vendor:
        lines.append(f"- **Vendor:** {report.context.vendor}")
    if report.context.log_format:
        lines.append(f"- **Formato:** {report.context.log_format}")
    if report.context.incident_name:
        lines.append(f"- **Incidente:** {report.context.incident_name}")
    if report.context.host_name:
        lines.append(f"- **Host:** {report.context.host_name}")
    if report.context.host_ip:
        lines.append(f"- **IP host:** {report.context.host_ip}")
    if report.context.user_name:
        lines.append(f"- **Utente:** {report.context.user_name}")
    if report.context.malware_id:
        lines.append(f"- **Malware ID:** {report.context.malware_id}")
    if report.context.malware_type:
        lines.append(f"- **Malware type:** {report.context.malware_type}")
    lines.append("")

    if report.context.vendor == "FortiGate":
        lines.append("## Evento FortiGate")
        lines.append("")
        if report.context.event_name:
            lines.append(f"- **Evento CEF:** {report.context.event_name}")
        if report.context.cef_severity is not None:
            lines.append(f"- **Severità CEF:** {report.context.cef_severity}")
        if report.context.device_external_id:
            lines.append(f"- **Device ID:** {report.context.device_external_id}")
        if report.context.log_description:
            lines.append(f"- **Descrizione:** {report.context.log_description}")
        if report.context.message:
            lines.append(f"- **Messaggio:** {report.context.message}")
        extra = report.context.extra or {}
        if extra.get("FTNTFGTlevel"):
            lines.append(f"- **Livello:** {extra['FTNTFGTlevel']}")
        if extra.get("FTNTFGTsubtype"):
            lines.append(f"- **Sottotipo:** {extra['FTNTFGTsubtype']}")
        if extra.get("cat"):
            lines.append(f"- **Categoria:** {extra['cat']}")
        lines.append("")

    if report.context.vendor == "MicrosoftDefender":
        lines.append("## Alert Microsoft Defender")
        lines.append("")
        extra = report.context.extra or {}
        if report.context.event_name:
            lines.append(f"- **Detector:** {report.context.event_name}")
        if extra.get("severity_text"):
            lines.append(f"- **Severità:** {extra['severity_text']}")
        if extra.get("product_name"):
            lines.append(f"- **Prodotto:** {extra['product_name']}")
        if extra.get("incident_id"):
            lines.append(f"- **Incident ID:** {extra['incident_id']}")
        if extra.get("status"):
            lines.append(f"- **Stato:** {extra['status']}")
        if extra.get("categories"):
            lines.append(f"- **Categorie:** {', '.join(extra['categories'])}")
        if extra.get("mitre_techniques"):
            lines.append(
                f"- **MITRE ATT&CK:** {', '.join(extra['mitre_techniques'])}"
            )
        if report.context.log_description:
            lines.append(f"- **Descrizione:** {report.context.log_description}")
        lines.append("")

    internal = report.internal_ips
    if internal:
        lines.append("## Rete interna (non inviata a VirusTotal)")
        lines.append("")
        for ar in internal:
            lines.append(f"- `{ar.artifact.normalized_value}` — {', '.join(ar.artifact.provenance)}")
        lines.append("")
        lines.append(
            "> Suggerimento: correlare questi IP con log DHCP/DNS/firewall interni."
        )
        lines.append("")

    by_type: dict[ArtifactType, list] = {}
    for ar in report.artifacts:
        by_type.setdefault(ar.artifact.type, []).append(ar)

    lines.append("## Artefatti estratti")
    lines.append("")
    for art_type in ArtifactType:
        group = by_type.get(art_type, [])
        if not group:
            continue
        lines.append(f"### {art_type.value}")
        lines.append("")
        for ar in group:
            scope_note = ""
            if ar.artifact.scope == ArtifactScope.INTERNAL:
                scope_note = " _(interno)_"
            lines.append(f"- **{ar.artifact.value}**{scope_note}")
            lines.append(f"  - Provenienza: {', '.join(ar.artifact.provenance)}")
            for enr in ar.enrichments:
                status = enr.status.value
                summary = enr.summary or ""
                lines.append(f"  - VT [{status}]: {summary}")
                if enr.data.get("permalink"):
                    lines.append(f"    - Link: {enr.data['permalink']}")
                if enr.data.get("last_analysis_stats"):
                    stats = enr.data["last_analysis_stats"]
                    lines.append(
                        f"    - Stats: malicious={stats.get('malicious', 0)}, "
                        f"harmless={stats.get('harmless', 0)}, "
                        f"undetected={stats.get('undetected', 0)}"
                    )
        lines.append("")

    enrichable = report.enrichable_artifacts
    enriched = [a for a in enrichable if a.enrichments]
    lines.append("## Riepilogo arricchimento")
    lines.append("")
    lines.append(f"- Artefatti arricchibili (pubblici): {len(enrichable)}")
    lines.append(f"- Con risultato enricher: {len(enriched)}")
    lines.append("")

    return "\n".join(lines)


def write_markdown_report(report: IncidentReport, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_markdown(report), encoding="utf-8")


def print_summary(report: IncidentReport) -> None:
    print(json.dumps({
        "source": report.source_file,
        "artifacts": len(report.artifacts),
        "internal_ips": len(report.internal_ips),
        "enrichable": len(report.enrichable_artifacts),
    }, indent=2))
