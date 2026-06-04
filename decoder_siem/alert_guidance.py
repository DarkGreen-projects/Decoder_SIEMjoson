from __future__ import annotations

from decoder_siem.models import IncidentContext, IncidentReport
from decoder_siem.table_export import classify_artifact


def _count_malicious(report: IncidentReport) -> int:
    return sum(1 for ar in report.artifacts if classify_artifact(ar) == "malicious")


def _defender_guidance(ctx: IncidentContext, report: IncidentReport) -> tuple[str, str, list[str]]:
    """Returns (alert_type_label, description, focus_bullets)."""
    detector = (ctx.event_name or "").lower()
    category = (ctx.message or "").lower()
    title = (ctx.incident_name or "").lower()
    extra = ctx.extra or {}
    mitre = extra.get("mitre_techniques") or []
    malicious = _count_malicious(report)

    if "ldap" in detector or "reconnaissance" in title:
        return (
            "Microsoft Defender — Ricognizione LDAP (Identity)",
            "Rilevata attività di enumerazione verso gruppi AD privilegiati (es. Schema Admins, Enterprise Admins). "
            "Tipico di fase **Discovery** (MITRE) e spesso precursore di movimento laterale o privilege escalation.",
            [
                "IP/host **sorgente** che esegue le query LDAP (elementi in rosso = verificati malevoli su VT).",
                "Domain controller **destinazione** e dominio AD coinvolto.",
                "Gruppi AD elencati come target della ricognizione.",
                "Correlare con log SIEM: Event ID 1644/2889, traffico verso LDAP (389/636).",
                "Verificare se l'origine è un server noto, un pentest autorizzato o un compromesso.",
            ],
        )

    if category == "discovery" or "discovery" in str(extra.get("categories", [])).lower():
        return (
            "Microsoft Defender — Discovery",
            "Alert orientato alla **ricognizione** dell'ambiente (utenti, gruppi, risorse). "
            "Valutare se il comportamento è legittimo (inventario, tool amministrativi) o sospetto.",
            [
                "Entità sorgente (IP, host, utente) e risorse consultate.",
                "Tecniche MITRE indicate nel riepilogo.",
                "IOC in rosso nella colonna elementi analizzati.",
            ],
        )

    if "malware" in title or "malicious" in detector:
        return (
            "Microsoft Defender — Malware / esecuzione sospetta",
            "Segnalazione legata a file o comportamento potenzialmente malevolo su endpoint o identità.",
            [
                "Hash e percorsi file (se presenti) marcati in rosso.",
                "Host coinvolto e utente in esecuzione.",
                "Isolare l'endpoint e avviare hunting su stesso hash utente/rete.",
            ],
        )

    if malicious > 0:
        return (
            f"Microsoft Defender — {ctx.incident_name or 'Alert generico'}",
            "Alert Microsoft 365 Defender con almeno un IOC segnato come sospetto da VirusTotal.",
            [
                "Priorità agli elementi **rosso carmino** nella lista analizzati.",
                "Incident ID e link portale nel JSON originale.",
                f"Tecniche MITRE: {', '.join(mitre) if mitre else 'vedi riepilogo'}.",
            ],
        )

    return (
        f"Microsoft Defender — {ctx.incident_name or 'Alert'}",
        "Alert da Microsoft Defender for Identity / M365. Usa detector e categoria per inquadrare il tipo di minaccia.",
        [
            "Host e IP interni vs esterni nella tabella.",
            "Evidence e ruoli (source/destination) nel JSON.",
            "Elementi VT in rosso per IOC pubblici.",
        ],
    )


def _fortigate_guidance(ctx: IncidentContext, report: IncidentReport) -> tuple[str, str, list[str]]:
    event = (ctx.event_name or ctx.incident_name or "").lower()
    extra = ctx.extra or {}
    level = (extra.get("FTNTFGTlevel") or "").lower()
    malicious = _count_malicious(report)

    if "event:system" in event or "system" in event:
        return (
            "FortiGate — Evento di sistema",
            "Log infrastrutturale del firewall (es. riavvio, spegnimento, errore hardware). "
            "Di solito **non** indica compromissione da solo; serve contesto operativo.",
            [
                "Hostname del firewall e device ID.",
                "Messaggio/logdesc (es. power off, upgrade, failover).",
                "Correlare con manutenzione programmata o problemi elettrici/UPS.",
                "Se inaspettato: verificare accesso amministrativo e integrità configurazione.",
            ],
        )

    if "traffic" in event or "forward" in event or "utm" in event:
        return (
            "FortiGate — Traffico / UTM",
            "Evento legato a sessioni di rete o servizi UTM (URL, AV, IPS). "
            "Focus su chi parla con chi e se il traffico è stato bloccato o consentito.",
            [
                "IP sorgente e destinazione; URL/domini in rosso.",
                "Policy e azione (accept/deny) nel log completo.",
                "Host interni coinvolti e orario dell'evento.",
            ],
        )

    if level == "critical" or level == "warning":
        return (
            f"FortiGate — {ctx.event_name or 'Evento'} ({level})",
            f"Evento FortiGate con severità **{level}**. Verificare impatto su disponibilità e sicurezza perimetrale.",
            [
                "Elementi in rosso = IOC con rilevazioni VT.",
                "IP esterni vs RFC1918 nella tabella.",
                "Descrizione testuale nel campo logdesc/msg.",
            ],
        )

    return (
        f"FortiGate — {ctx.event_name or 'Log CEF'}",
        "Log syslog/CEF da FortiGate. Il tipo di evento (campo Name) guida l'analisi.",
        [
            "IOC di rete (IP, URL) evidenziati in rosso.",
            "Device e hostname del firewall.",
            "Incrocio con ticket di change management se evento di sistema.",
        ],
    )


def _cynet_guidance(ctx: IncidentContext, report: IncidentReport) -> tuple[str, str, list[str]]:
    name = (ctx.incident_name or "").lower()
    malicious = _count_malicious(report)

    if "malicious" in name or "infected" in name or "malware" in name:
        return (
            "Cynet — File / binario malevolo",
            "Rilevazione EDR su file o processo sospetto (possibile drop, esecuzione o file infetto).",
            [
                "SHA-256 del file infetto e processo parent (rosso = VT malevolo).",
                "Percorsi file e utente/host coinvolti.",
                "Verificare remediation Cynet (quarantena/rinomina) e propagazione su altri endpoint.",
                "Cercare stesso hash su altri host nel SIEM.",
            ],
        )

    if "prevention" in name or "eps" in name:
        return (
            "Cynet — Prevenzione EPS",
            "L'agente ha tentato di bloccare una minaccia in esecuzione o in scrittura su disco.",
            [
                "File e processo bloccato; esito prevention nel JSON.",
                "Host IP interno e utente.",
                "Hash in rosso per conferma multi-engine.",
            ],
        )

    if malicious > 0:
        return (
            f"Cynet — {ctx.incident_name or 'Incidente'}",
            "Incidente Cynet con IOC segnalati come malevoli da VirusTotal.",
            [
                "Priorità a hash, IP pubblici e path in rosso.",
                "HostName e HostIp per scope dell'incidente.",
                "Malware ID/type nel riepilogo.",
            ],
        )

    return (
        f"Cynet — {ctx.incident_name or 'Incidente'}",
        "Alert dal sensore Cynet EPS. Leggi il nome incidente per la categoria (file, rete, comportamento).",
        [
            "SHA-256 e percorsi nella tabella.",
            "IP host interno (verde) vs IOC esterni.",
            "Descrizione testuale IncidentDescription per timeline.",
        ],
    )


def _generic_guidance(ctx: IncidentContext, report: IncidentReport) -> tuple[str, str, list[str]]:
    malicious = _count_malicious(report)
    return (
        "Alert generico",
        "Formato riconosciuto parzialmente. Usa tabella e elementi colorati per la prioritizzazione.",
        [
            f"Artefatti con rilevazioni VT malevole: **{malicious}**.",
            "Elementi in rosso carmino = attenzione immediata.",
            "Elementi in verde = non malevoli o non verificabili su VT.",
        ],
    )


def build_alert_guidance(ctx: IncidentContext, report: IncidentReport) -> tuple[str, str, list[str]]:
    vendor = ctx.vendor
    if vendor == "MicrosoftDefender":
        return _defender_guidance(ctx, report)
    if vendor == "FortiGate":
        return _fortigate_guidance(ctx, report)
    if vendor == "Cynet":
        return _cynet_guidance(ctx, report)
    return _generic_guidance(ctx, report)


def alert_guidance_to_markdown(ctx: IncidentContext, report: IncidentReport) -> str:
    if not ctx.vendor and not report.artifacts:
        return (
            "### Guida all'alert\n\n"
            "_Dopo l'analisi comparirà una breve spiegazione del tipo di alert "
            "e su cosa concentrare l'indagine._"
        )

    label, description, focus = build_alert_guidance(ctx, report)
    lines = [
        "### Guida all'alert",
        "",
        f"**Tipo:** {label}",
        "",
        description,
        "",
        "**Dove portare l'attenzione:**",
    ]
    for item in focus:
        lines.append(f"- {item}")

    malicious = _count_malicious(report)
    if malicious:
        lines.append("")
        lines.append(
            f"> **Nota:** {malicious} elemento/i con rilevazioni sospette su VirusTotal "
            "(rosso carmino nella colonna a destra)."
        )

    return "\n".join(lines)
