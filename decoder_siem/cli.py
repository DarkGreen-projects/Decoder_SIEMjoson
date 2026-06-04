from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import typer
from dotenv import load_dotenv

from decoder_siem import __version__
from decoder_siem.enrichment_config import EnrichmentConfig
from decoder_siem.pipeline import build_report
from decoder_siem.report import print_summary, write_json_report, write_markdown_report

load_dotenv()

INPUT_EXTENSIONS = {".json", ".log", ".txt", ".cef"}


app = typer.Typer(
    name="decoder-siem",
    help="Estrae IOC da JSON/CEF incidenti SIEM e li arricchisce via OSINT (VT, AbuseIPDB, OTX, URLhaus).",
    no_args_is_help=True,
)


def _collect_input_paths(path: Path, recursive: bool) -> list[Path]:
    if path.is_file():
        if path.suffix.lower() not in INPUT_EXTENSIONS:
            raise typer.BadParameter(
                f"Estensione non supportata: {path.suffix}. "
                f"Usa: {', '.join(sorted(INPUT_EXTENSIONS))}"
            )
        return [path]
    if not path.is_dir():
        raise typer.BadParameter(f"Percorso non trovato: {path}")
    files: list[Path] = []
    for ext in INPUT_EXTENSIONS:
        pattern = f"**/*{ext}" if recursive else f"*{ext}"
        files.extend(path.glob(pattern))
    files = sorted(set(files))
    if not files:
        raise typer.BadParameter(
            f"Nessun file supportato in {path} "
            f"(estensioni: {', '.join(sorted(INPUT_EXTENSIONS))})"
        )
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
    input_path: Path = typer.Argument(..., help="File JSON/CEF/log o cartella"),
    output: Optional[Path] = typer.Option(
        None, "-o", "--output", help="File report JSON di output"
    ),
    markdown: Optional[Path] = typer.Option(
        None, "--markdown", "-m", help="File report Markdown"
    ),
    recursive: bool = typer.Option(
        False, "--recursive", "-r", help="Cerca file ricorsivamente nelle cartelle"
    ),
) -> None:
    """Estrae IOC senza chiamare API esterne."""
    paths = _collect_input_paths(input_path, recursive)
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
    input_path: Path = typer.Argument(..., help="File JSON/CEF/log o cartella"),
    output: Optional[Path] = typer.Option(
        None, "-o", "--output", help="File report JSON di output"
    ),
    markdown: Optional[Path] = typer.Option(
        None, "--markdown", "-m", help="File report Markdown"
    ),
    no_enrich: bool = typer.Option(
        False, "--no-enrich", help="Equivalente a extract-only (senza API OSINT)"
    ),
    recursive: bool = typer.Option(
        False, "--recursive", "-r", help="Cerca file ricorsivamente nelle cartelle"
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
    """Estrae IOC e arricchisce via fonti OSINT configurate in .env."""
    config = EnrichmentConfig.from_env()
    if requests_per_minute != config.vt_requests_per_minute:
        config = EnrichmentConfig(
            vt_api_key=config.vt_api_key,
            abuseipdb_api_key=config.abuseipdb_api_key,
            otx_api_key=config.otx_api_key,
            urlhaus_auth_key=config.urlhaus_auth_key,
            vt_requests_per_minute=requests_per_minute,
            osint_requests_per_minute=config.osint_requests_per_minute,
            abuseipdb_max_age_days=config.abuseipdb_max_age_days,
        )

    if not no_enrich and not config.has_any_enricher():
        typer.echo(
            "Avviso: nessuna chiave OSINT in .env (VT, AbuseIPDB, OTX, URLhaus). "
            "Eseguo solo estrazione.",
            err=True,
        )
        no_enrich = True
    elif not no_enrich and not config.vt_api_key:
        typer.echo(
            "Avviso: VT_API_KEY non impostata; arricchimento senza VirusTotal.",
            err=True,
        )

    paths = _collect_input_paths(input_path, recursive)
    for p in paths:
        out = output or _default_output(p)
        report = build_report(
            p,
            enrich=not no_enrich,
            config=config,
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
