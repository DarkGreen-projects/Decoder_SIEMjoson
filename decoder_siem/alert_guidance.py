from __future__ import annotations

from dataclasses import dataclass, field

from decoder_siem.models import (
    ArtifactReport,
    ArtifactScope,
    ArtifactType,
    IncidentContext,
    IncidentReport,
)
from decoder_siem.table_export import classify_artifact

COLOR_MALICIOUS = "#960018"


@dataclass
class ReportFacts:
    malicious: list[str] = field(default_factory=list)
    benign_public: list[str] = field(default_factory=list)
    internal_ips: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    ad_groups: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    other_ids: list[str] = field(default_factory=list)


def _count_malicious(report: IncidentReport) -> int:
    return sum(1 for ar in report.artifacts if classify_artifact(ar) == "malicious")


def _fmt_list(items: list[str], limit: int = 5) -> str:
    unique = []
    seen: set[str] = set()
    for item in items:
        if item and item not in seen:
            seen.add(item)
            unique.append(item)
    if not unique:
        return "_non estratti_"
    shown = unique[:limit]
    text = ", ".join(f"`{x}`" for x in shown)
    if len(unique) > limit:
        text += f" (+{len(unique) - limit} altri)"
    return text


def extract_report_facts(report: IncidentReport) -> ReportFacts:
    facts = ReportFacts()
    for ar in report.artifacts:
        art = ar.artifact
        verdict = classify_artifact(ar)
        label = f"{art.type.value}: {art.value}"

        if art.type == ArtifactType.IP:
            if art.scope == ArtifactScope.INTERNAL:
                facts.internal_ips.append(art.value)
            elif verdict == "malicious":
                facts.malicious.append(label)
            else:
                facts.benign_public.append(art.value)
        elif art.type == ArtifactType.HOSTNAME:
            facts.hostnames.append(art.value)
        elif art.type == ArtifactType.DOMAIN:
            facts.domains.append(art.value)
        elif art.type in (
            ArtifactType.HASH_SHA256,
            ArtifactType.HASH_SHA1,
            ArtifactType.HASH_MD5,
        ):
            if verdict == "malicious":
                facts.malicious.append(label)
            else:
                facts.hashes.append(art.value)
        elif art.type == ArtifactType.FILE_PATH:
            facts.paths.append(art.value)
        elif art.type == ArtifactType.URL:
            facts.urls.append(art.value)
        elif art.type == ArtifactType.USERNAME:
            if art.context.get("evidence_type") == "security_group":
                facts.ad_groups.append(art.value)
            else:
                facts.usernames.append(art.value)
        elif art.type == ArtifactType.MALWARE_LABEL:
            facts.other_ids.append(art.value)
        elif art.type == ArtifactType.OTHER:
            facts.other_ids.append(art.value)

    return facts


def _defender_guidance(
    ctx: IncidentContext, report: IncidentReport, facts: ReportFacts
) -> tuple[str, str, list[str], list[str], list[str]]:
    detector = (ctx.event_name or "").lower()
    title = (ctx.incident_name or "").lower()
    extra = ctx.extra or {}
    mitre = extra.get("mitre_techniques") or []
    incident_id = extra.get("incident_id")
    severity = extra.get("severity_text") or ctx.severity
    product = extra.get("product_name") or "Microsoft Defender"

    key_facts: list[str] = []
    if ctx.incident_name:
        key_facts.append(f"Titolo alert: **{ctx.incident_name}**")
    if ctx.event_name:
        key_facts.append(f"Detector: `{ctx.event_name}`")
    if incident_id:
        key_facts.append(f"Incident ID: `{incident_id}`")
    if severity:
        key_facts.append(f"Severità: **{severity}**")
    if mitre:
        key_facts.append(f"MITRE ATT&CK: {', '.join(f'`{t}`' for t in mitre)}")
    if facts.internal_ips:
        key_facts.append(f"IP interni coinvolti: {_fmt_list(facts.internal_ips)}")
    if facts.benign_public:
        key_facts.append(f"IP pubblici (non VT malevoli): {_fmt_list(facts.benign_public)}")
    if facts.malicious:
        key_facts.append(f"IOC con VT sospetto: {_fmt_list(facts.malicious)}")
    if facts.hostnames:
        key_facts.append(f"Host: {_fmt_list(facts.hostnames)}")
    if facts.domains:
        key_facts.append(f"Dominio AD: {_fmt_list(facts.domains)}")
    if facts.ad_groups:
        key_facts.append(f"Gruppi AD enumerati: {_fmt_list(facts.ad_groups, limit=8)}")

    actions: list[str] = []

    if "ldap" in detector or "reconnaissance" in title:
        src = facts.internal_ips[0] if facts.internal_ips else None
        dc = next((h for h in facts.hostnames if h.upper() == h or "dc" in h.lower()), None)
        domain = facts.domains[0] if facts.domains else None

        desc = (
            f"Da **{product}**: un attore con origine "
            f"**{src or 'IP nella tabella'}** ha eseguito query LDAP anomale verso "
            f"**{dc or 'il domain controller'}**"
            + (f" nel dominio `{domain}`" if domain else "")
            + ". Obiettivo tipico: mappare gruppi ad alto privilegio prima di un attacco."
        )

        focus = [
            f"Identificare il sistema **{src}** — è un server noto, workstation amministrativa o host non inventariato?",
            f"Su **{dc or 'DC'}**: rivedere log Directory Service (1644, 2889) nell'intervallo `{ctx.date_in or 'timestamp alert'}`",
            "Confermare se le query mirano a gruppi privilegiati elencati sopra (Schema/Enterprise Admins, DC, GPO Owners)",
            "Cercare autenticazioni Kerberos/NTLM da quella sorgente verso altri server nelle ore successive",
        ]
        if facts.malicious:
            focus.insert(0, f"Priorità massima: IOC in VT malevolo → {_fmt_list(facts.malicious, 3)}")

        actions = [
            f"Isolare o limitare temporaneamente la connettività LDAP da `{src}` se non giustificata",
            f"Verificare sessioni attive e tool (BloodHound, AdFind, PowerView) su `{src}`",
            "Notificare il team AD per revisione membership dei gruppi target",
            "Aprire incidente correlato su M365 se esiste movimento verso altri asset Critical",
        ]
        return (
            "Microsoft Defender — Ricognizione LDAP (Identity)",
            desc,
            focus,
            key_facts,
            actions,
        )

    if "malware" in title or "malicious" in detector:
        host = facts.hostnames[0] if facts.hostnames else ctx.host_name
        desc = (
            f"Alert **{ctx.incident_name}** su endpoint/identità. "
            f"Host principale: **{host or 'vedi tabella'}**. "
            "Possibile esecuzione o file malevolo."
        )
        focus = [
            f"Hash file: {_fmt_list(facts.hashes) if facts.hashes else _fmt_list([m.split(': ', 1)[-1] for m in facts.malicious if 'hash' in m])}",
            f"Percorsi: {_fmt_list(facts.paths, 3)}",
            f"Utente: {_fmt_list(facts.usernames) if facts.usernames else ctx.user_name or 'N/D'}",
        ]
        actions = [
            "Isolare l'host dalla rete se hash confermato malevolo",
            "Raccogliere campione file e timeline processo parent",
            "Hunting globale su stesso SHA-256 / stesso path",
        ]
        return (
            f"Microsoft Defender — {ctx.incident_name or 'Malware'}",
            desc,
            focus,
            key_facts,
            actions,
        )

    desc = (
        f"Alert **{ctx.incident_name or 'generico'}** ({product}). "
        f"Categoria: **{ctx.message or 'N/D'}**. "
        "Usa gli elementi chiave sotto per restringere l'indagine."
    )
    focus = [
        "Elementi in **rosso carmino** (colonna destra) = priorità VT",
        f"Host/IP nella tabella: partire da `{ctx.host_ip or facts.internal_ips[0] if facts.internal_ips else 'N/D'}`",
    ]
    actions = ["Aprire l'alert nel portale M365 Security dal link nel JSON originale"]
    return (
        f"Microsoft Defender — {ctx.incident_name or 'Alert'}",
        desc,
        focus,
        key_facts,
        actions,
    )


def _fortigate_guidance(
    ctx: IncidentContext, report: IncidentReport, facts: ReportFacts
) -> tuple[str, str, list[str], list[str], list[str]]:
    event = ctx.event_name or ctx.incident_name or "evento"
    extra = ctx.extra or {}
    level = extra.get("FTNTFGTlevel") or ""
    subtype = extra.get("FTNTFGTsubtype") or ""

    key_facts = [
        f"Firewall: **{ctx.host_name or 'N/D'}**",
        f"Device ID: `{ctx.device_external_id or 'N/D'}`",
        f"Evento CEF: `{event}`",
    ]
    if level:
        key_facts.append(f"Livello log: **{level}**")
    if subtype:
        key_facts.append(f"Sottotipo: `{subtype}`")
    if ctx.log_description:
        key_facts.append(f"Descrizione: **{ctx.log_description}**")
    if ctx.message:
        key_facts.append(f"Dettaglio: _{ctx.message[:200]}{'…' if len(ctx.message or '') > 200 else ''}_")

    if "event:system" in event.lower() or "system" in event.lower():
        desc = (
            f"Il firewall **{ctx.host_name}** ha registrato un evento di **sistema**: "
            f"_{ctx.log_description or 'vedi messaggio'}_. "
            f"{'Messaggio: ' + ctx.message if ctx.message else ''} "
            "Non è un alert malware di per sé: indica un cambiamento sul dispositivo."
        )
        focus = [
            f"Verificare se il reboot/power-off su `{ctx.host_name}` era pianificato (change ticket, UPS, manutenzione)",
            "Controllare ultimo accesso amministrativo (SSH/HTTPS) al FortiGate prima dell'evento",
            "Se imprevisto: backup config recente, confronto integrità, stato HA/cluster",
        ]
        if facts.malicious:
            focus.insert(0, f"Attenzione: IOC di rete sospetti nello stesso log batch → {_fmt_list(facts.malicious)}")

        actions = [
            "Confermare con operations/network se intervento fisico o elettrico",
            "Dopo ripartenza: verificare servizi VPN, policy e routing attivi",
            "Documentare in CMDB timestamp e causa root",
        ]
        return ("FortiGate — Evento di sistema", desc, focus, key_facts, actions)

    if "traffic" in event.lower() or "utm" in event.lower():
        desc = (
            f"Sessione/traffico su **{ctx.host_name}**: evento `{event}`. "
            f"Sorgente → destinazione da tabella (IP interni: {_fmt_list(facts.internal_ips)})."
        )
        focus = [
            f"IP esterni / URL: {_fmt_list(facts.benign_public + [m for m in facts.malicious])}",
            "Verificare azione firewall: accept, deny, ips, av nel log completo",
            "Correlare con utente/application ID se presente nel CEF esteso",
        ]
        actions = [
            "Bloccare temporaneamente IOC in rosso se non business-critical",
            "Estrarre PCAP o log flow se disponibile per quella sessione",
        ]
        return (f"FortiGate — {event}", desc, focus, key_facts, actions)

    return (
        f"FortiGate — {event}",
        f"Log da `{ctx.host_name}` — analizzare campi extension e IOC in tabella.",
        ["IOC rosso = priorità", "IP interni = ambito LAN da correlare"],
        key_facts,
        ["Rivedere policy FortiOS coinvolta"],
    )


def _cynet_guidance(
    ctx: IncidentContext, report: IncidentReport, facts: ReportFacts
) -> tuple[str, str, list[str], list[str], list[str]]:
    name = ctx.incident_name or "Incidente Cynet"
    key_facts = [
        f"Incidente: **{name}**",
        f"Host: **{ctx.host_name or 'N/D'}** (`{ctx.host_ip or 'IP N/D'}`)",
    ]
    if ctx.user_name:
        key_facts.append(f"Utente: `{ctx.user_name}`")
    if ctx.malware_id:
        key_facts.append(f"Firma: **{ctx.malware_id}**")
    if ctx.malware_type:
        key_facts.append(f"Tipo: `{ctx.malware_type}`")
    if facts.hashes:
        key_facts.append(f"SHA-256: {_fmt_list(facts.hashes, 3)}")
    if facts.paths:
        key_facts.append(f"File: {_fmt_list(facts.paths, 2)}")
    if facts.malicious:
        key_facts.append(f"VT malevolo: {_fmt_list(facts.malicious)}")

    infected = facts.paths[0] if facts.paths else "file indicato nel JSON"
    proc_hash = facts.hashes[1] if len(facts.hashes) > 1 else (facts.hashes[0] if facts.hashes else "N/D")

    if "malicious" in name.lower() or "infected" in name.lower():
        desc = (
            f"Cynet EPS su **{ctx.host_name}** (`{ctx.host_ip}`): rilevato file sospetto "
            f"`{infected}`"
            + (f", firma **{ctx.malware_id}**" if ctx.malware_id else "")
            + f". Processo correlato (hash): `{proc_hash}`."
        )
        focus = [
            f"Validare su VT lo SHA del file infetto (primo hash in elenco)",
            f"Controllare se `{infected}` è su share di rete — rischio propagazione",
            f"Parent process / utente `{ctx.user_name or 'N/D'}`: legittimo per quell'operazione?",
            "Verificare remediation Cynet (.cynet, quarantena) e stato su console",
        ]
        actions = [
            f"Hunting su tutti gli endpoint per hash `{facts.hashes[0] if facts.hashes else 'SHA-256'}`",
            "Bloccare esecuzione da quella share se non necessaria",
            "Coinvolgere utente/proprietario file per origine del documento",
        ]
        return ("Cynet — File infetto / binario malevolo", desc, focus, key_facts, actions)

    desc = f"Incidente Cynet **{name}** sull'host **{ctx.host_name}**."
    focus = [f"IOC prioritari: {_fmt_list(facts.malicious) if facts.malicious else 'nessuno VT malevolo'}"]
    actions = ["Aprire ticket su console Cynet con ClientDbId / ScanGroup dal JSON"]
    return (f"Cynet — {name}", desc, focus, key_facts, actions)


def _email_guidance(
    ctx: IncidentContext, report: IncidentReport, facts: ReportFacts
) -> tuple[str, str, list[str], list[str], list[str]]:
    extra = ctx.extra or {}
    analysis = extra.get("email_analysis") or {}
    verdict = analysis.get("verdict", "other")
    criticality = analysis.get("criticality", 0)
    indicators = analysis.get("indicators") or []
    auth = analysis.get("auth") or {}

    key_facts = [
        f"From: `{ctx.mail_from or 'N/D'}`",
        f"Reply-To: `{ctx.reply_to or 'N/D'}`",
        f"Subject: `{ctx.subject or 'N/D'}`",
        f"SPF/DKIM/DMARC: {auth.get('spf', 'N/D')}/{auth.get('dkim', 'N/D')}/{auth.get('dmarc', 'N/D')}",
        f"Hop Received: {extra.get('hop_count', 'N/D')}",
    ]
    if facts.malicious:
        key_facts.append(f"IOC OSINT malevoli: {_fmt_list(facts.malicious)}")

    if verdict == "phishing":
        desc = (
            f"Header email classificati come **phishing** (criticità **{criticality}/100**). "
            f"Indicatori: {', '.join(indicators[:4]) or 'allineamento identità / auth debole'}."
        )
        focus = [
            "Verificare link e allegati nel corpo (non analizzati in profondità in v1)",
            "Controllare mailbox destinatario: regole di inoltro sospette",
            f"Correlare IP mittente: {_fmt_list(facts.benign_public + facts.malicious)}",
            "Valutare blocco dominio mittente su gateway email",
        ]
        actions = [
            "Isolare messaggio in quarantena e avvisare utente destinatario",
            "Cercare stesso mittente/Reply-To su altre mailbox (hunting)",
            "Aprire ticket SOC con header completi e verdetto",
        ]
        return ("Email — Phishing", desc, focus, key_facts, actions)

    if verdict == "spam":
        desc = (
            f"Header email classificati come **spam** (criticità **{criticality}/100**). "
            "Pattern bulk/marketing o autenticazione debole."
        )
        focus = [
            "Valutare policy anti-spam e blocklist dominio mittente",
            f"Auth header: SPF={auth.get('spf')}, DKIM={auth.get('dkim')}",
            "Verificare se utente si è iscritto volontariamente a liste",
        ]
        actions = [
            "Aggiungere mittente a blocklist se ripetuto",
            "Segnalare a team email security per tuning regole",
        ]
        return ("Email — Spam", desc, focus, key_facts, actions)

    desc = (
        f"Email classificata come **altro** (criticità **{criticality}/100**). "
        "Può essere legittima o richiedere verifica manuale."
    )
    focus = [
        "Rivedere indicatori in pannello analisi email",
        f"IOC estratti per OSINT: {_fmt_list(facts.domains + facts.benign_public)}",
    ]
    if criticality >= 30:
        focus.append("Criticità moderata: validare manualmente mittente e link")
    actions = [
        "Archiviare esito analisi con header originali",
        "Escalation solo se IOC OSINT risultano malevoli",
    ]
    return ("Email — Altro / da verificare", desc, focus, key_facts, actions)


def _generic_guidance(
    ctx: IncidentContext, report: IncidentReport, facts: ReportFacts
) -> tuple[str, str, list[str], list[str], list[str]]:
    malicious = _count_malicious(report)
    return (
        "Alert generico",
        f"Vendor: **{ctx.vendor or 'sconosciuto'}**. Elementi estratti: {len(report.artifacts)}.",
        [
            f"IOC VT malevoli: **{malicious}** (rosso {COLOR_MALICIOUS})",
            f"IP interni: {_fmt_list(facts.internal_ips)}",
        ],
        [
            f"Host: {_fmt_list(facts.hostnames)}",
            f"Hash: {_fmt_list(facts.hashes)}",
        ],
        ["Rivedere provenienza in tabella dettaglio"],
    )


def build_alert_guidance(
    ctx: IncidentContext, report: IncidentReport
) -> tuple[str, str, list[str], list[str], list[str]]:
    facts = extract_report_facts(report)
    vendor = ctx.vendor
    if vendor == "MicrosoftDefender":
        return _defender_guidance(ctx, report, facts)
    if vendor == "FortiGate":
        return _fortigate_guidance(ctx, report, facts)
    if vendor == "Cynet":
        return _cynet_guidance(ctx, report, facts)
    if vendor == "EmailHeaders":
        return _email_guidance(ctx, report, facts)
    return _generic_guidance(ctx, report, facts)


def alert_guidance_to_markdown(ctx: IncidentContext, report: IncidentReport) -> str:
    if not ctx.vendor and not report.artifacts:
        return (
            "### Guida all'alert\n\n"
            "_Dopo l'analisi comparirà una spiegazione contestuale con host, IP, hash "
            "e azioni suggerite per questo specifico alert._"
        )

    label, description, focus, key_facts, actions = build_alert_guidance(ctx, report)
    lines = [
        "### Guida all'alert",
        "",
        f"**Tipo:** {label}",
        "",
        "**Cosa è successo (questo alert)**",
        "",
        description,
        "",
        "**Elementi chiave estratti**",
        "",
    ]
    for item in key_facts:
        lines.append(f"- {item}")

    lines.extend(["", "**Dove portare l'attenzione**", ""])
    for item in focus:
        lines.append(f"- {item}")

    if actions:
        lines.extend(["", "**Azioni suggerite (ordine consigliato)**", ""])
        for i, action in enumerate(actions, 1):
            lines.append(f"{i}. {action}")

    malicious = _count_malicious(report)
    if malicious:
        lines.append("")
        lines.append(
            f"> **{malicious}** IOC con rilevazioni VirusTotal sospette — "
            "cercali in **rosso carmino** nella colonna *Elementi analizzati*."
        )
    elif ctx.vendor == "FortiGate" and "system" in (ctx.event_name or "").lower():
        lines.append("")
        lines.append(
            "> Questo evento di sistema di solito **non** richiede hunting malware; "
            "priorità a causa operativa e accessi amministrativi."
        )

    return "\n".join(lines)
