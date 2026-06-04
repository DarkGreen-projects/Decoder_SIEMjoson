from __future__ import annotations

import os

from dotenv import load_dotenv

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

GUI_CSS = """
.artifacts-panel { line-height: 1.5; }
.artifacts-panel h4 { margin-top: 0; }
.summary-panel { min-width: 280px; }
"""


def run_analysis(text: str) -> tuple[str, str, list[list[str]], str]:
    """Restituisce (markdown riepilogo, html IOC, righe tabella, errore)."""
    if not text or not text.strip():
        return EMPTY_MARKDOWN, EMPTY_HTML, [], "Inserisci del testo da analizzare."

    api_key = os.getenv("VT_API_KEY")
    error_msg = EMPTY_ERROR
    if not api_key:
        error_msg = (
            "VT_API_KEY non configurata: crea il file .env con la chiave VirusTotal. "
            "L'estrazione verrà eseguita ma gli IOC non saranno verificati da VT."
        )

    try:
        report = build_report_from_text(
            text,
            enrich=True,
            api_key=api_key,
        )
    except ValueError as exc:
        return EMPTY_MARKDOWN, EMPTY_HTML, [], str(exc)
    except Exception as exc:  # noqa: BLE001
        return EMPTY_MARKDOWN, EMPTY_HTML, [], f"Errore durante l'analisi: {exc}"

    rows = report_to_rows(report)
    summary = context_to_markdown(
        report.context,
        artifact_count=len(report.artifacts),
    )
    if api_key:
        summary += "\n\n_VirusTotal: arricchimento attivo._"
    artifacts_html = report_to_colored_html(report)

    return summary, artifacts_html, rows, error_msg


def clear_all() -> tuple[str, str, str, list[list[str]], str]:
    """Reset completo dell'interfaccia."""
    return "", EMPTY_MARKDOWN, EMPTY_HTML, [], EMPTY_ERROR


def main() -> None:
    import gradio as gr

    with gr.Blocks(title="Decoder SIEM", theme=gr.themes.Soft(), css=GUI_CSS) as app:
        gr.Markdown(
            "# Decoder SIEM\n"
            "Incolla JSON (Cynet, Microsoft Defender) o log CEF/syslog (FortiGate), "
            "poi premi **Analizza**. VirusTotal è sempre attivo se `VT_API_KEY` è in `.env`."
        )

        with gr.Row():
            text_input = gr.Textbox(
                label="Testo da analizzare",
                placeholder='{"Cynet": {...}} oppure <189>... CEF:0|Fortinet|...',
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
            interactive=False,
            wrap=True,
        )

        clear_btn = gr.Button("Pulisci")

        analyze_btn.click(
            fn=run_analysis,
            inputs=[text_input],
            outputs=[summary_md, artifacts_html, results_table, error_box],
        )
        text_input.submit(
            fn=run_analysis,
            inputs=[text_input],
            outputs=[summary_md, artifacts_html, results_table, error_box],
        )

        clear_btn.click(
            fn=clear_all,
            outputs=[text_input, summary_md, artifacts_html, results_table, error_box],
        )

    app.launch(server_name="127.0.0.1")


if __name__ == "__main__":
    main()
