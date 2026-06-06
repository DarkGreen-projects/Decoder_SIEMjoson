from __future__ import annotations

from dataclasses import dataclass, field

from decoder_siem.correlation import (
    build_correlated_entities,
    entity_facts_from_report,
    entity_role_label,
)
from decoder_siem.models import (
    ArtifactReport,
    ArtifactScope,
    ArtifactType,
    IncidentContext,
    IncidentReport,
)
from decoder_siem.input_guard import safe_md
from decoder_siem.table_export import classify_artifact

COLOR_MALICIOUS = "#960018"


@dataclass
class EntityFacts:
    role: str
    role_label: str
    display_name: str | None = None
    path: str | None = None
    hash_value: str | None = None
    vt_verdict: str | None = None


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
    entities: list[EntityFacts] = field(default_factory=list)


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
    text = ", ".join(f"`{safe_md(x)}`" for x in shown)
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

    entities = build_correlated_entities(report.artifacts)
    for item in entity_facts_from_report(report, entities):
        facts.entities.append(
            EntityFacts(
                role=str(item.get("role") or "standalone"),
                role_label=str(item.get("role_label") or ""),
                display_name=item.get("display_name"),
                path=item.get("path"),
                hash_value=item.get("hash"),
                vt_verdict=item.get("vt_verdict"),
            )
        )

    return facts


def _entity_by_role(facts: ReportFacts, role: str) -> EntityFacts | None:
    for entity in facts.entities:
        if entity.role == role:
            return entity
    return None


def _client_reporting_plan(
    ctx: IncidentContext,
    report: IncidentReport,
    facts: ReportFacts,
) -> list[str]:
    malicious_count = _count_malicious(report)
    infected = _entity_by_role(facts, "infected_file")
    processes = [
        e for e in facts.entities if e.role in ("parent_process", "grandparent_process", "process")
    ]

    lines: list[str] = []

    host = ctx.host_name or "host N/D"
    user = ctx.user_name or "utente N/D"
    vendor = ctx.vendor or "sconosciuto"
    lines.append(
        f"**Sintesi evento:** alert **{vendor}** su **{host}** "
        f"(utente/contesto: `{user}`)."
    )

    if infected and (infected.path or infected.hash_value):
        vt = infected.vt_verdict or "non verificato"
        name = infected.display_name or infected.path or "file"
        lines.append(
            f"**Evidenza primaria:** `{name}`"
            + (f" — percorso `{infected.path}`" if infected.path else "")
            + (f" — SHA `{infected.hash_value}`" if infected.hash_value else "")
            + f" — esito VT: **{vt}**."
        )
    elif facts.malicious:
        lines.append(
            f"**Evidenza primaria:** IOC di rete/file con VT sospetto: "
            f"{_fmt_list(facts.malicious, 3)}."
        )
    else:
        lines.append(
            "**Evidenza primaria:** nessun IOC VT malevolo; validare contesto operativo."
        )

    if processes:
        proc_bits = []
        for proc in processes[:3]:
            label = proc.role_label or entity_role_label(proc.role)
            bit = label
            if proc.hash_value:
                bit += f" `{proc.hash_value[:16]}…`"
            if proc.path:
                bit += f" ({proc.path})"
            proc_bits.append(bit)
        lines.append(f"**Catena di esecuzione:** {' → '.join(proc_bits)}.")

    if malicious_count and (ctx.malware_id or infected):
        lines.append(
            "**Raccomandazione comunicazione:** incidente **confermato** — "
            "segnalare al cliente con hash, percorso e azioni di containment già avviate."
        )
    elif malicious_count:
        lines.append(
            "**Raccomandazione comunicazione:** IOC sospetti su VT — "
            "aprire ticket cliente con evidenze in tabella (elementi in rosso carmino)."
        )
    elif ctx.severity and ctx.severity >= 4:
        lines.append(
            "**Raccomandazione comunicazione:** severità alta ma VT non conclusivo — "
            "completare investigazione interna prima di escalation al cliente."
        )
    elif facts.malicious or malicious_count:
        lines.append(
            "**Raccomandazione comunicazione:** valutare blocco IOC e aggiornamento cliente "
            "se il contesto business conferma l'anomalia."
        )
    else:
        lines.append(
            "**Raccomandazione comunicazione:** probabile falso positivo o evento informativo — "
            "documentare esito e comunicare al cliente solo se policy interna lo richiede."
        )

    return lines


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

    infected_entity = _entity_by_role(facts, "infected_file")
    infected = (
        infected_entity.path
        or infected_entity.display_name
        if infected_entity
        else (facts.paths[0] if facts.paths else "file indicato nel JSON")
    )
    proc_entity = _entity_by_role(facts, "parent_process")
    proc_hash = (
        proc_entity.hash_value
        if proc_entity and proc_entity.hash_value
        else (facts.hashes[1] if len(facts.hashes) > 1 else (facts.hashes[0] if facts.hashes else "N/D"))
    )
    infected_hash = infected_entity.hash_value if infected_entity else (facts.hashes[0] if facts.hashes else "SHA-256")

    if "malicious" in name.lower() or "infected" in name.lower():
        desc = (
            f"Cynet EPS su **{ctx.host_name}** (`{ctx.host_ip}`): rilevato file sospetto "
            f"`{infected}`"
            + (f", firma **{ctx.malware_id}**" if ctx.malware_id else "")
            + f". Processo correlato (hash): `{proc_hash}`."
        )
        focus = [
            f"File infetto: hash `{infected_hash}` (lookup VT sullo SHA, percorso non duplicato)",
            f"Controllare se `{infected}` è su share di rete — rischio propagazione",
            f"Parent process / utente `{ctx.user_name or 'N/D'}`: legittimo per quell'operazione?",
            "Verificare remediation Cynet (.cynet, quarantena) e stato su console",
        ]
        actions = [
            f"Hunting su tutti gli endpoint per hash `{infected_hash}`",
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

    content_profile = analysis.get("content_profile") or extra.get("content_profile", "headers_only")
    attachments_count = analysis.get("attachments_count") or extra.get("attachments_count", 0)
    content_indicators = analysis.get("content_indicators") or []

    key_facts = [
        f"From: `{ctx.mail_from or 'N/D'}`",
        f"Reply-To: `{ctx.reply_to or 'N/D'}`",
        f"Subject: `{ctx.subject or 'N/D'}`",
        f"SPF/DKIM/DMARC: {auth.get('spf', 'N/D')}/{auth.get('dkim', 'N/D')}/{auth.get('dmarc', 'N/D')}",
        f"Hop Received: {extra.get('hop_count', 'N/D')}",
        f"Ambito analisi: {content_profile}",
    ]
    if attachments_count:
        key_facts.append(f"Allegati analizzati: {attachments_count} (hash SHA256)")
    if content_indicators:
        key_facts.append(f"Segnali corpo/allegati: {_fmt_list(content_indicators, limit=3)}")
    if facts.malicious:
        key_facts.append(f"IOC OSINT malevoli: {_fmt_list(facts.malicious)}")

    if verdict == "phishing":
        desc = (
            f"Header email classificati come **phishing** (criticità **{criticality}/100**). "
            f"Indicatori: {', '.join(indicators[:4]) or 'allineamento identità / auth debole'}."
        )
        focus = [
            "Verificare link nel corpo HTML e hash allegati in tabella (VT/OSINT)",
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

    if verdict == "unclassifiable":
        detail = analysis.get("detail") or "Header insufficienti o malformati"
        desc = (
            f"Email **non classificabile** (criticità **{criticality}/100**). "
            f"{detail}"
        )
        focus = [
            "Verificare di aver incollato l'intero blocco «Mostra originale»",
            "Controllare che siano presenti From, Received e Message-ID",
            "Ripetere l'analisi con header completi prima di escalation",
        ]
        actions = [
            "Richiedere header completi al mittente o dal gateway email",
            "Non basare blocchi automatici solo su questa analisi",
        ]
        return ("Email — Non classificabile", desc, focus, key_facts, actions)

    scope = analysis.get("detail") or f"ambito: {content_profile}"
    desc = (
        f"Email classificata come **safe** (criticità **{criticality}/100**). "
        f"{scope}; infrastrutture note escluse da OSINT automatico."
    )
    focus = [
        "Confermare coerenza mittente/contesto con l'utente se il messaggio è inatteso",
        f"IOC analizzati: {_fmt_list(facts.domains + facts.benign_public)}",
        "Domini noti (Google, Microsoft, …): link VT disponibile senza chiamate API",
    ]
    actions = [
        "Archiviare esito se coerente con attività legittima attesa",
        "Escalation solo se compaiono IOC OSINT malevoli o contenuto sospetto nel corpo",
    ]
    return ("Email — Safe", desc, focus, key_facts, actions)


def _raw_ioc_guidance(
    ctx: IncidentContext, report: IncidentReport, facts: ReportFacts
) -> tuple[str, str, list[str], list[str], list[str]]:
    malicious = _count_malicious(report)
    public_ips = [
        ar.artifact.value
        for ar in report.artifacts
        if ar.artifact.type == ArtifactType.IP
        and ar.artifact.scope != ArtifactScope.INTERNAL
    ]
    desc = (
        f"Analisi diretta di **{len(report.artifacts)}** IOC forniti manualmente "
        "(IP, hash, URL o dominio). Ogni elemento è stato arricchito con le stesse "
        "fonti OSINT usate per gli alert completi."
    )
    focus = [
        f"IOC VT malevoli: **{malicious}** (rosso {COLOR_MALICIOUS})",
        f"IP pubblici: {_fmt_list(public_ips)}",
        f"Hash analizzati: {_fmt_list(facts.hashes)}",
        f"Domini/URL: {_fmt_list(facts.domains + facts.urls)}",
    ]
    key_facts = [
        f"IOC totali: {len(report.artifacts)}",
        f"IP interni (non arricchiti VT): {_fmt_list(facts.internal_ips)}",
    ]
    actions = [
        "Verificare il contesto operativo di ogni IOC prima di blocchi automatici",
        "Correlare hash e IP con altri eventi SIEM o ticket recenti",
        "Escalation se compaiono IOC malevoli senza spiegazione legittima nota",
    ]
    return ("IOC diretti", desc, focus, key_facts, actions)


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
    if vendor == "RawIOC":
        return _raw_ioc_guidance(ctx, report, facts)
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

    facts = extract_report_facts(report)
    client_plan = _client_reporting_plan(ctx, report, facts)
    if client_plan:
        lines.extend(["", "### Piano movimento / Segnalazione cliente", ""])
        for item in client_plan:
            lines.append(f"- {item}")

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
