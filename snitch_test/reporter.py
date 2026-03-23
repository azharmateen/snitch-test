"""Generate reports in multiple formats: terminal, SARIF, JSON, markdown."""

import json
from datetime import datetime, timezone
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from snitch_test.analyzer import AnalysisReport, Finding, Severity


# ─── Terminal (Rich) ─────────────────────────────────────────────

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "[!!]",
    Severity.HIGH: "[!]",
    Severity.MEDIUM: "[~]",
    Severity.LOW: "[.]",
    Severity.INFO: "[i]",
}

RISK_BAR_LENGTH = 20


def _risk_bar(score: int) -> Text:
    filled = int(score / 100 * RISK_BAR_LENGTH)
    empty = RISK_BAR_LENGTH - filled
    bar = Text()
    color = "green" if score < 25 else "yellow" if score < 50 else "red" if score < 80 else "bold red"
    bar.append("\u2588" * filled, style=color)
    bar.append("\u2591" * empty, style="dim")
    bar.append(f" {score}/100", style=color)
    return bar


def print_terminal_report(report: AnalysisReport, console: Optional[Console] = None) -> None:
    """Print a rich terminal report."""
    c = console or Console()

    c.print()
    c.print(Panel.fit(
        "[bold]snitch-test Security Report[/bold]",
        border_style="cyan",
    ))

    # Summary
    risk_style = "green" if report.risk_level == "safe" else \
                 "yellow" if report.risk_level in ("low", "medium") else "bold red"
    c.print(f"\n  [bold]Risk Level:[/bold] [{risk_style}]{report.risk_level.upper()}[/{risk_style}]")
    c.print("  [bold]Risk Score:[/bold] ", end="")
    c.print(_risk_bar(report.risk_score))
    c.print(f"  [bold]Summary:[/bold] {report.summary}")
    c.print(f"  [bold]Duration:[/bold] {report.scan_duration:.1f}s")
    c.print(f"  [bold]Events:[/bold] {report.total_events} total, {report.suspicious_events} suspicious")
    c.print(f"  [bold]Leaked:[/bold] {report.leaked_count} credentials")

    if not report.findings:
        c.print("\n  [green bold]All clear! No issues found.[/green bold]\n")
        return

    # Findings table
    c.print()
    table = Table(title="Findings", show_lines=True)
    table.add_column("Severity", width=10)
    table.add_column("Title", min_width=30)
    table.add_column("Credential", width=20)
    table.add_column("Destination", width=20)

    for f in report.findings:
        color = SEVERITY_COLORS[f.severity]
        table.add_row(
            Text(f.severity.value.upper(), style=color),
            f.title,
            f.credential or "-",
            f.destination or "-",
        )

    c.print(table)

    # Detailed findings
    c.print("\n[bold]Details:[/bold]")
    for i, f in enumerate(report.findings, 1):
        color = SEVERITY_COLORS[f.severity]
        icon = SEVERITY_ICONS[f.severity]
        c.print(f"\n  [{color}]{icon} #{i}: {f.title}[/{color}]")
        c.print(f"      {f.description}")
        if f.evidence:
            c.print(f"      [dim]Evidence: {f.evidence[:150]}[/dim]")
        c.print(f"      [italic]Recommendation: {f.recommendation}[/italic]")

    c.print()


# ─── JSON ────────────────────────────────────────────────────────

def to_json(report: AnalysisReport) -> str:
    """Convert report to JSON format."""
    return json.dumps({
        "risk_score": report.risk_score,
        "risk_level": report.risk_level,
        "summary": report.summary,
        "scan_duration": report.scan_duration,
        "total_events": report.total_events,
        "suspicious_events": report.suspicious_events,
        "leaked_credentials": report.leaked_count,
        "findings": [
            {
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "credential": f.credential,
                "destination": f.destination,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
            }
            for f in report.findings
        ],
    }, indent=2)


# ─── Markdown ────────────────────────────────────────────────────

def to_markdown(report: AnalysisReport) -> str:
    """Convert report to Markdown format."""
    lines = [
        "# snitch-test Security Report",
        "",
        f"**Risk Level:** {report.risk_level.upper()}",
        f"**Risk Score:** {report.risk_score}/100",
        f"**Summary:** {report.summary}",
        f"**Duration:** {report.scan_duration:.1f}s",
        "",
    ]

    if not report.findings:
        lines.append("> All clear! No issues found.")
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")
    lines.append("| # | Severity | Title | Credential | Destination |")
    lines.append("|---|----------|-------|------------|-------------|")

    for i, f in enumerate(report.findings, 1):
        lines.append(
            f"| {i} | {f.severity.value.upper()} | {f.title} | "
            f"{f.credential or '-'} | {f.destination or '-'} |"
        )

    lines.append("")
    lines.append("## Details")
    lines.append("")

    for i, f in enumerate(report.findings, 1):
        lines.append(f"### {i}. {f.title}")
        lines.append(f"**Severity:** {f.severity.value.upper()}")
        lines.append(f"**Description:** {f.description}")
        if f.evidence:
            lines.append(f"**Evidence:** `{f.evidence[:150]}`")
        lines.append(f"**Recommendation:** {f.recommendation}")
        lines.append("")

    return "\n".join(lines)


# ─── SARIF (GitHub Security) ────────────────────────────────────

def to_sarif(report: AnalysisReport) -> str:
    """Convert report to SARIF format for GitHub Security tab."""
    severity_map = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "none",
    }

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "snitch-test",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/snitch-test",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }

    rules_seen = set()
    run = sarif["runs"][0]

    for i, f in enumerate(report.findings):
        rule_id = f"SNITCH{i+1:03d}"

        if rule_id not in rules_seen:
            rules_seen.add(rule_id)
            run["tool"]["driver"]["rules"].append({
                "id": rule_id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "help": {"text": f.recommendation},
                "defaultConfiguration": {
                    "level": severity_map.get(f.severity, "warning")
                },
            })

        result = {
            "ruleId": rule_id,
            "level": severity_map.get(f.severity, "warning"),
            "message": {"text": f"{f.description}\n\nRecommendation: {f.recommendation}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "package.json"  # Generic; in real use, point to lockfile
                        }
                    }
                }
            ],
        }

        if f.evidence:
            result["fingerprints"] = {"primaryLocationLineHash": f.evidence[:60]}

        run["results"].append(result)

    return json.dumps(sarif, indent=2)
