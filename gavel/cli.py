"""Gavel CLI - Command line interface with ASCII art"""

import click
import sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint
import json
from typing import Optional
from dotenv import load_dotenv

from gavel.core import verify_report, batch_verify_reports
from gavel.utils.parser import parse_report_file

# Load environment variables
load_dotenv()

console = Console()

ASCII_ART = """
    ╔═══════════════════════════════════════╗
    ║                                       ║
    ║              ⚖️  GAVEL ⚖️             ║
    ║                                       ║
    ║    AI-Powered Vulnerability Triage   ║
    ║                                       ║
    ╚═══════════════════════════════════════╝

         ████████
        ██      ██
       ██        ██
       ██  ⚒️   ██
       ██        ██
        ██      ██
         ████████
           ████
           ████
           ████
          ██  ██
         ██    ██
        ██      ██
       ████████████
"""


def print_banner():
    """Print ASCII art banner"""
    banner_text = Text(ASCII_ART, style="bold cyan")
    console.print(banner_text)


def print_result(verdict: str, reasoning: str, output_format: str = "text", report_id: Optional[str] = None):
    """Print verification result in specified format"""
    if output_format == "json":
        result = {
            "verdict": verdict,
            "reasoning": reasoning,
            "report_id": report_id,
        }
        print(json.dumps(result, indent=2))
    else:
        # Text format with rich styling
        verdict_style = "bold green" if verdict == "VALID" else "bold red"

        panel_content = f"[{verdict_style}]{verdict}[/{verdict_style}]\n\n"
        panel_content += f"[dim]Reasoning:[/dim] {reasoning}"

        if report_id:
            panel_content += f"\n\n[dim]Report ID:[/dim] {report_id}"

        panel = Panel(
            panel_content,
            title="🔨 Verification Result",
            border_style=verdict_style,
            expand=False
        )
        console.print(panel)


@click.command()
@click.option(
    "--report", "-r",
    type=click.Path(exists=True),
    help="Path to vulnerability report file"
)
@click.option(
    "--codebase", "-c",
    required=True,
    help="Path to codebase (local path or GitHub URL)"
)
@click.option(
    "--output-poc",
    is_flag=True,
    help="Generate a Proof of Concept instead of just verification"
)
@click.option(
    "--model",
    type=click.Choice(["opus-4.5", "sonnet-4.5"], case_sensitive=False),
    default="opus-4.5",
    help="AI model to use (default: opus-4.5)"
)
@click.option(
    "--batch",
    type=click.Path(exists=True),
    help="Process multiple reports from a directory"
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    help="Output format (default: text)"
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable verbose logging"
)
@click.option(
    "--no-banner",
    is_flag=True,
    help="Disable ASCII art banner"
)
def main(
    report: Optional[str],
    codebase: str,
    output_poc: bool,
    model: str,
    batch: Optional[str],
    output_format: str,
    verbose: bool,
    no_banner: bool
):
    """
    Gavel - AI-Powered Vulnerability Report Verification

    Verify vulnerability reports against codebases using AI analysis.

    Examples:

        gavel -r report.txt -c /path/to/project

        gavel -r report.txt -c https://github.com/user/repo

        gavel --batch reports/ -c /path/to/project

        gavel -r report.txt -c /path/to/project --output-poc
    """
    try:
        # Print banner unless disabled
        if not no_banner and output_format == "text":
            print_banner()

        # Validate inputs
        if not batch and not report:
            console.print("[bold red]Error:[/bold red] Either --report or --batch is required", style="red")
            sys.exit(1)

        # Batch processing
        if batch:
            if verbose:
                console.print(f"[dim]Processing batch from:[/dim] {batch}")

            batch_path = Path(batch)
            if not batch_path.is_dir():
                console.print("[bold red]Error:[/bold red] Batch path must be a directory", style="red")
                sys.exit(1)

            # Find all report files (supports .txt, .md, .html)
            report_files = (
                list(batch_path.glob("*.txt")) +
                list(batch_path.glob("*.md")) +
                list(batch_path.glob("*.html")) +
                list(batch_path.glob("*.htm"))
            )

            if not report_files:
                console.print("[bold red]Error:[/bold red] No report files found in batch directory", style="red")
                sys.exit(1)

            if verbose:
                console.print(f"[dim]Found {len(report_files)} reports to process[/dim]")

            # Process batch
            results = batch_verify_reports(
                report_files=[str(f) for f in report_files],
                codebase_path=codebase,
                model=model,
                generate_poc=output_poc,
                verbose=verbose
            )

            # Output results
            if output_format == "json":
                print(json.dumps(results, indent=2))
            else:
                for result in results:
                    print_result(
                        result["verdict"],
                        result["reasoning"],
                        output_format,
                        result.get("report_id")
                    )
                    console.print()  # Blank line between results

        # Single report processing
        else:
            if verbose:
                console.print(f"[dim]Processing report:[/dim] {report}")
                console.print(f"[dim]Codebase:[/dim] {codebase}")
                console.print(f"[dim]Model:[/dim] {model}")

            # Parse and verify report
            report_content = parse_report_file(report)

            if verbose:
                console.print("[dim]Analyzing codebase and verifying report...[/dim]")

            result = verify_report(
                report=report_content,
                codebase_path=codebase,
                model=model,
                generate_poc=output_poc,
                verbose=verbose
            )

            # Print result
            print_result(
                result.verdict,
                result.reasoning,
                output_format,
                result.report_id
            )

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}", style="red")
        if verbose:
            console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    main()
