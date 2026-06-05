from __future__ import annotations

import inspect
from typing import Any

from dotenv import load_dotenv

from decoder_siem.alert_guidance import alert_guidance_to_markdown
from decoder_siem.enrichment_config import EnrichmentConfig
from decoder_siem.pipeline import build_report_from_text
from decoder_siem.table_export import (
    TABLE_HEADERS,
    context_to_markdown,
    report_to_colored_html,
    report_to_rows,
)

load_dotenv()

EMPTY_MARKDOWN = "### Riepilogo incidente\n\n_Incolla un alert e premi **Analizza**._"
EMPTY_HTML = (
    '<div class="artifacts-panel">'
    "<h4>Elementi analizzati</h4>"
    "<p><i>I risultati appariranno qui dopo l'analisi.</i></p></div>"
)
EMPTY_ERROR = ""
EMPTY_ALERT_GUIDANCE = (
    "### Guida all'alert\n\n"
    "_Dopo l'analisi comparirà una breve spiegazione del tipo di alert "
    "e su cosa concentrare l'indagine._"
)

GUI_CSS = """
.artifacts-panel { line-height: 1.5; }
.artifacts-panel a { color: inherit; text-decoration: underline; }
.artifacts-panel a:hover { opacity: 0.85; }
.artifacts-panel h4 { margin-top: 0; }
.summary-panel { min-width: 280px; }
.footer-copyright {
  text-align: right;
  color: #6b6b6b;
  font-size: 12px;
  margin-top: 1.5rem;
  padding-right: 8px;
}
.footer-copyright a:hover {
  text-decoration: underline;
}
footer {
  display: none !important;
}
"""


def _launch_kwargs(app: Any) -> dict[str, Any]:
    """Build launch kwargs that hide Gradio's default footer across versions."""
    kwargs: dict[str, Any] = {"server_name": "127.0.0.1"}
    params = inspect.signature(app.launch).parameters
    if "footer_links" in params:
        kwargs["footer_links"] = []
    elif "show_api" in params:
        kwargs["show_api"] = False
    return kwargs


def _launch_app(app: Any) -> None:
    app.launch(**_launch_kwargs(app))


def run_analysis(text: str) -> tuple[str, str, list[list[str]], str, str]:
    """Restituisce (riepilogo, html IOC, tabella, errore, guida alert)."""
    if not text or not text.strip():
        return (
            EMPTY_MARKDOWN,
            EMPTY_HTML,
            [],
            "Inserisci del testo da analizzare.",
            EMPTY_ALERT_GUIDANCE,
        )

    config = EnrichmentConfig.from_env()
    warnings: list[str] = []
    if not config.vt_api_key:
        warnings.append("VT_API_KEY non configurata (VirusTotal disattivato).")
    if not config.abuseipdb_api_key:
        warnings.append("ABUSEIPDB_API_KEY non configurata (AbuseIPDB disattivato).")
    if not config.otx_api_key:
        warnings.append("OTX_API_KEY non configurata (AlienVault OTX disattivato).")
    if not config.urlhaus_auth_key:
        warnings.append(
            "URLHAUS_AUTH_KEY non configurata (URLhaus disattivato; "
            "chiave gratuita su https://auth.abuse.ch/)."
        )
    error_msg = " ".join(warnings) if warnings else EMPTY_ERROR

    try:
        report = build_report_from_text(
            text,
            enrich=True,
            config=config,
        )
    except ValueError as exc:
        return EMPTY_MARKDOWN, EMPTY_HTML, [], str(exc), EMPTY_ALERT_GUIDANCE
    except Exception as exc:  # noqa: BLE001
        return (
            EMPTY_MARKDOWN,
            EMPTY_HTML,
            [],
            f"Errore durante l'analisi: {exc}",
            EMPTY_ALERT_GUIDANCE,
        )

    rows = report_to_rows(report)
    summary = context_to_markdown(
        report.context,
        artifact_count=len(report.artifacts),
    )
    artifacts_html = report_to_colored_html(report)
    guidance = alert_guidance_to_markdown(report.context, report)

    return summary, artifacts_html, rows, error_msg, guidance


def clear_all() -> tuple[str, str, str, list[list[str]], str, str]:
    """Reset completo dell'interfaccia."""
    return "", EMPTY_MARKDOWN, EMPTY_HTML, [], EMPTY_ERROR, EMPTY_ALERT_GUIDANCE


def main() -> None:
    import gradio as gr

    with gr.Blocks(title="Decoder SIEM", theme=gr.themes.Soft(), css=GUI_CSS) as app:
        gr.Markdown(
            "# Decoder SIEM\n"
            "Incolla JSON (Cynet, Microsoft Defender), log CEF/syslog (FortiGate) "
            "o **header email** (Mostra originale), poi premi **Analizza**."
        )

        with gr.Row():
            text_input = gr.Textbox(
                label="Testo da analizzare",
                placeholder='{"Cynet": {...}} | CEF:0|Fortinet|... | From: ...\\nReceived: ...',
                lines=14,
                scale=4,
            )
            analyze_btn = gr.Button("Analizza", variant="primary", scale=1)

        error_box = gr.Textbox(label="Messaggi", interactive=False, visible=True)

        with gr.Row(equal_height=False):
            summary_md = gr.Markdown(value=EMPTY_MARKDOWN, elem_classes=["summary-panel"])
            artifacts_html = gr.HTML(value=EMPTY_HTML)

        gr.Markdown("### Dettaglio tabellare")
        results_table = gr.Dataframe(
            headers=TABLE_HEADERS,
            datatype=["str"] * len(TABLE_HEADERS),
            column_widths=["6%"] * len(TABLE_HEADERS),
            interactive=False,
            wrap=True,
        )

        alert_guidance_md = gr.Markdown(value=EMPTY_ALERT_GUIDANCE)

        clear_btn = gr.Button("Pulisci")

        gr.HTML(
            '<div class="footer-copyright">'
            '© <a href="https://github.com/DarkGreen-projects" '
            'target="_blank" rel="noopener noreferrer" '
            'style="color:#6b6b6b; text-decoration:none;">Darkgreen</a>'
            "</div>",
            elem_classes=["footer-copyright"],
        )

        analyze_btn.click(
            fn=run_analysis,
            inputs=[text_input],
            outputs=[
                summary_md,
                artifacts_html,
                results_table,
                error_box,
                alert_guidance_md,
            ],
        )
        text_input.submit(
            fn=run_analysis,
            inputs=[text_input],
            outputs=[
                summary_md,
                artifacts_html,
                results_table,
                error_box,
                alert_guidance_md,
            ],
        )

        clear_btn.click(
            fn=clear_all,
            outputs=[
                text_input,
                summary_md,
                artifacts_html,
                results_table,
                error_box,
                alert_guidance_md,
            ],
        )

    _launch_app(app)


if __name__ == "__main__":
    main()
