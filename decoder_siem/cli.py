from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import typer
from dotenv import load_dotenv

from decoder_siem import __version__
from decoder_siem.pipeline import build_report
from decoder_siem.report import print_summary, write_json_report, write_markdown_report

load_dotenv()

app = typer.Typer(
    name="decoder-siem",
    help="Estrae IOC da JSON incidenti SIEM e li arricchisce via VirusTotal.",
    no_args_is_help=True,
)


def _collect_json_paths(path: Path, recursive: bool) -> list[Path]:
    if path.is_file():
        return [path]
    if not path.is_dir():
        raise typer.BadParameter(f"Percorso non trovato: {path}")
    pattern = "**/*.json" if recursive else "*.json"
    files = sorted(path.glob(pattern))
    if not files:
        raise typer.BadParameter(f"Nessun file JSON in {path}")
    return files


def _default_output(input_path: Path) -> Path:
    stem = input_path.stem
    return Path("out") / f"{stem}_report.json"


@app.command("version")
def version_cmd() -> None:
    """Mostra la versione del pacchetto."""
    typer.echo(__version__)


@app.command("extract-only")
def extract_only(
    input_path: Path = typer.Argument(..., help="File JSON o cartella"),
    output: Optional[Path] = typer.Option(
        None, "-o", "--output", help="File report JSON di output"
    ),
    markdown: Optional[Path] = typer.Option(
        None, "--markdown", "-m", help="File report Markdown"
    ),
    recursive: bool = typer.Option(
        False, "--recursive", "-r", help="Cerca JSON ricorsivamente nelle cartelle"
    ),
) -> None:
    """Estrae IOC senza chiamare API esterne."""
    paths = _collect_json_paths(input_path, recursive)
    for p in paths:
        out = output or _default_output(p)
        report = build_report(p, enrich=False)
        write_json_report(report, out)
        typer.echo(f"Report JSON: {out}")
        if markdown:
            write_markdown_report(report, markdown)
            typer.echo(f"Report Markdown: {markdown}")
        print_summary(report)


@app.command("analyze")
def analyze(
    input_path: Path = typer.Argument(..., help="File JSON o cartella"),
    output: Optional[Path] = typer.Option(
        None, "-o", "--output", help="File report JSON di output"
    ),
    markdown: Optional[Path] = typer.Option(
        None, "--markdown", "-m", help="File report Markdown"
    ),
    no_enrich: bool = typer.Option(
        False, "--no-enrich", help="Equivalente a extract-only (senza VirusTotal)"
    ),
    recursive: bool = typer.Option(
        False, "--recursive", "-r", help="Cerca JSON ricorsivamente nelle cartelle"
    ),
    cache_dir: Optional[Path] = typer.Option(
        None, "--cache-dir", help="Directory cache risposte VirusTotal"
    ),
    requests_per_minute: int = typer.Option(
        int(os.getenv("VT_REQUESTS_PER_MINUTE", "4")),
        "--rpm",
        help="Richieste VirusTotal per minuto",
    ),
) -> None:
    """Estrae IOC e arricchisce via VirusTotal (se API key presente)."""
    api_key = os.getenv("VT_API_KEY")
    if not no_enrich and not api_key:
        typer.echo(
            "Avviso: VT_API_KEY non impostata. Eseguo solo estrazione.",
            err=True,
        )
        no_enrich = True

    paths = _collect_json_paths(input_path, recursive)
    for p in paths:
        out = output or _default_output(p)
        report = build_report(
            p,
            enrich=not no_enrich,
            api_key=api_key,
            requests_per_minute=requests_per_minute,
            cache_dir=cache_dir,
        )
        write_json_report(report, out)
        typer.echo(f"Report JSON: {out}")
        md_path = markdown or out.with_suffix(".md")
        if markdown is not None or not no_enrich:
            write_markdown_report(report, md_path)
            typer.echo(f"Report Markdown: {md_path}")
        print_summary(report)


if __name__ == "__main__":
    app()
