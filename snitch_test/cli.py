"""CLI interface for snitch-test."""

import json
import os
import shutil
import sys
from pathlib import Path

import click
from rich.console import Console

from snitch_test.canary import generate_canary_set
from snitch_test.sandbox import build_sandbox_context, detect_project_type, get_capture_script
from snitch_test.monitor import run_sandbox_with_monitoring
from snitch_test.analyzer import analyze_results
from snitch_test.reporter import print_terminal_report, to_json, to_markdown, to_sarif

console = Console()

REPORT_DIR = Path.home() / ".snitch-test"
LAST_REPORT = REPORT_DIR / "last_report.json"


def save_report(report_json: str) -> None:
    """Save report to ~/.snitch-test/."""
    REPORT_DIR.mkdir(exist_ok=True)
    LAST_REPORT.write_text(report_json)


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """snitch-test: Test if your dependencies are stealing environment variables."""
    pass


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--timeout", "-t", default=300, help="Sandbox timeout in seconds")
@click.option("--format", "-f", "fmt", type=click.Choice(["terminal", "json", "markdown", "sarif"]), default="terminal")
@click.option("--output", "-o", type=click.Path(), help="Write report to file")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--dry-run", is_flag=True, help="Show what would be tested without running Docker")
def scan(path: str, timeout: int, fmt: str, output: str, verbose: bool, dry_run: bool):
    """Scan a project's dependencies for credential theft.

    PATH is the project directory to scan (default: current directory).
    """
    project_path = os.path.abspath(path)

    console.print(f"\n[bold cyan]snitch-test[/bold cyan] scanning: {project_path}\n")

    # Detect project type
    try:
        ptype, image, install_cmd = detect_project_type(project_path)
        console.print(f"  [green]Detected:[/green] {ptype} project")
        console.print(f"  [green]Image:[/green] {image}")
        console.print(f"  [green]Install:[/green] {install_cmd}")
    except ValueError as e:
        console.print(f"  [red]Error:[/red] {e}")
        sys.exit(1)

    # Generate canary credentials
    canaries = generate_canary_set()
    console.print(f"  [green]Canaries:[/green] {len(canaries)} fake credentials generated")

    if verbose:
        for c in canaries:
            console.print(f"    [{c.category}] {c.name}")

    if dry_run:
        console.print("\n  [yellow]Dry run mode - not executing Docker sandbox[/yellow]")
        console.print(f"  Would build image: {image}")
        console.print(f"  Would run: {install_cmd}")
        console.print(f"  With {len(canaries)} canary env vars")
        return

    # Check Docker availability
    if not shutil.which("docker"):
        console.print("\n  [red]Error: Docker is not installed or not in PATH[/red]")
        console.print("  Install Docker: https://docs.docker.com/get-docker/")
        sys.exit(1)

    # Build sandbox context
    console.print("\n[yellow]Building sandbox...[/yellow]")
    capture_script = get_capture_script()
    context_dir = build_sandbox_context(project_path, canaries, capture_script)

    try:
        # Run sandbox with monitoring
        console.print("[yellow]Running sandbox (this may take a few minutes)...[/yellow]")
        monitor_result = run_sandbox_with_monitoring(
            context_dir,
            canaries,
            timeout=timeout,
            verbose=verbose,
        )

        if not monitor_result.success:
            console.print(f"\n  [red]Sandbox error:[/red] {monitor_result.error}")
            if "Docker not available" in str(monitor_result.error):
                console.print("  Make sure Docker daemon is running: docker info")
            sys.exit(1)

        # Analyze results
        console.print("[yellow]Analyzing results...[/yellow]")
        report = analyze_results(monitor_result, canaries)

        # Output report
        if fmt == "terminal":
            print_terminal_report(report, console)
        elif fmt == "json":
            report_str = to_json(report)
            if output:
                Path(output).write_text(report_str)
                console.print(f"[green]Report written to {output}[/green]")
            else:
                print(report_str)
        elif fmt == "markdown":
            report_str = to_markdown(report)
            if output:
                Path(output).write_text(report_str)
                console.print(f"[green]Report written to {output}[/green]")
            else:
                print(report_str)
        elif fmt == "sarif":
            report_str = to_sarif(report)
            if output:
                Path(output).write_text(report_str)
                console.print(f"[green]SARIF report written to {output}[/green]")
            else:
                print(report_str)

        # Save report for `snitch-test report` command
        save_report(to_json(report))

        # Exit code based on risk
        if report.risk_level in ("high", "critical"):
            sys.exit(1)

    finally:
        # Cleanup temp directory
        shutil.rmtree(context_dir, ignore_errors=True)


@cli.command()
@click.option("--format", "-f", "fmt", type=click.Choice(["terminal", "json", "markdown", "sarif"]), default="terminal")
@click.option("--output", "-o", type=click.Path(), help="Write report to file")
def report(fmt: str, output: str):
    """View the last scan report."""
    if not LAST_REPORT.exists():
        console.print("[yellow]No scan report found. Run 'snitch-test scan' first.[/yellow]")
        sys.exit(1)

    report_data = json.loads(LAST_REPORT.read_text())

    if fmt == "json":
        text = json.dumps(report_data, indent=2)
    elif fmt == "markdown":
        # Re-create a minimal markdown from JSON
        lines = [
            "# snitch-test Report (cached)",
            "",
            f"**Risk:** {report_data['risk_level'].upper()} ({report_data['risk_score']}/100)",
            f"**Summary:** {report_data['summary']}",
            "",
        ]
        if report_data.get("findings"):
            lines.append("## Findings")
            for i, f in enumerate(report_data["findings"], 1):
                lines.append(f"\n### {i}. [{f['severity'].upper()}] {f['title']}")
                lines.append(f.get("description", ""))
        text = "\n".join(lines)
    else:
        # Terminal display from cached JSON
        console.print(f"\n[bold cyan]Last Scan Report[/bold cyan]")
        console.print(f"  Risk: [{report_data['risk_level']}] {report_data['risk_level'].upper()} ({report_data['risk_score']}/100)")
        console.print(f"  {report_data['summary']}")
        if report_data.get("findings"):
            console.print(f"\n  [bold]Findings ({len(report_data['findings'])}):[/bold]")
            for i, f in enumerate(report_data["findings"], 1):
                sev = f["severity"].upper()
                console.print(f"    {i}. [{sev}] {f['title']}")
        console.print()
        return

    if output:
        Path(output).write_text(text)
        console.print(f"[green]Report written to {output}[/green]")
    else:
        print(text)


@cli.command()
def canaries():
    """Show sample canary credentials that would be generated."""
    creds = generate_canary_set("demo")
    table = console.status("[bold]Generating canaries...[/bold]")

    console.print("\n[bold cyan]Sample Canary Credentials[/bold cyan]\n")

    from rich.table import Table
    table = Table(show_lines=True)
    table.add_column("Name", style="bold")
    table.add_column("Category", style="cyan")
    table.add_column("Value Preview", max_width=50)
    table.add_column("Fingerprint", style="dim")

    for c in creds:
        preview = c.value[:47] + "..." if len(c.value) > 50 else c.value
        table.add_row(c.name, c.category, preview, c.fingerprint)

    console.print(table)
    console.print(f"\n  Total: {len(creds)} canary credentials\n")


if __name__ == "__main__":
    cli()
