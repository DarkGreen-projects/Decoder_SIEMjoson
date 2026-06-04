from __future__ import annotations

import os

from dotenv import load_dotenv

from decoder_siem.pipeline import build_report_from_text
from decoder_siem.table_export import (
    TABLE_HEADERS,
    context_to_markdown,
    report_to_rows,
)

load_dotenv()

EMPTY_MARKDOWN = "### Riepilogo incidente\n\n_Incolla un alert e premi **Analizza**._"
EMPTY_ERROR = ""


def run_analysis(
    text: str,
    enrich_vt: bool,
) -> tuple[str, list[list[str]], str]:
    """Esegue analisi e restituisce (markdown, righe tabella, messaggio errore)."""
    if not text or not text.strip():
        return EMPTY_MARKDOWN, [], "Inserisci del testo da analizzare."

    api_key = os.getenv("VT_API_KEY")
    if enrich_vt and not api_key:
        enrich_vt = False

    try:
        report = build_report_from_text(
            text,
            enrich=enrich_vt,
            api_key=api_key,
        )
    except ValueError as exc:
        return EMPTY_MARKDOWN, [], str(exc)
    except Exception as exc:  # noqa: BLE001
        return EMPTY_MARKDOWN, [], f"Errore durante l'analisi: {exc}"

    rows = report_to_rows(report)
    summary = context_to_markdown(
        report.context,
        artifact_count=len(report.artifacts),
    )
    if enrich_vt and api_key:
        summary += "\n\n_VirusTotal: arricchimento attivo._"
    elif enrich_vt:
        summary += "\n\n_VirusTotal: chiave API non configurata._"

    return summary, rows, EMPTY_ERROR


def clear_all() -> tuple[str, str, list[list[str]], str]:
    """Reset completo dell'interfaccia."""
    return "", EMPTY_MARKDOWN, [], EMPTY_ERROR


def main() -> None:
    import gradio as gr

    with gr.Blocks(title="Decoder SIEM", theme=gr.themes.Soft()) as app:
        gr.Markdown(
            "# Decoder SIEM\n"
            "Incolla JSON (Cynet, Microsoft Defender) o log CEF/syslog (FortiGate), "
            "poi premi **Analizza**."
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
        summary_md = gr.Markdown(value=EMPTY_MARKDOWN)
        results_table = gr.Dataframe(
            headers=TABLE_HEADERS,
            datatype=["str"] * len(TABLE_HEADERS),
            interactive=False,
            wrap=True,
        )

        with gr.Row():
            enrich_cb = gr.Checkbox(
                label="Arricchisci VirusTotal (richiede VT_API_KEY)",
                value=False,
            )
            clear_btn = gr.Button("Pulisci")

        analyze_btn.click(
            fn=run_analysis,
            inputs=[text_input, enrich_cb],
            outputs=[summary_md, results_table, error_box],
        )
        text_input.submit(
            fn=run_analysis,
            inputs=[text_input, enrich_cb],
            outputs=[summary_md, results_table, error_box],
        )

        clear_btn.click(
            fn=clear_all,
            outputs=[text_input, summary_md, results_table, error_box],
        )

    app.launch(server_name="127.0.0.1")


if __name__ == "__main__":
    main()
