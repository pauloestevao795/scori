"""scori CLI.

Available commands:
    scori scan --path .
    scori friction --path . [--format json|table|html] [--ci [--threshold N]]
    scori monitor --path . [--watch [--interval N]]

TODO v0.2+:
    scori update --dry-run      # simulate upgrade and re-score
    scori report                # rich HTML with charts
"""

from __future__ import annotations

import argparse
import json as jsonlib
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.table import Table

from . import __version__
from ._types import FrictionResult
from .friction import compute
from .scanner import scan

console = Console()


def _cmd_scan(args: argparse.Namespace) -> int:
    deps = scan(args.path)
    for d in deps:
        console.print(
            f"[bold]{d['name']}[/] {d['version_spec']} [dim]({d['source_file']})[/]"
        )
    return 0


def _fmt_cves(current: int, latest: int) -> str:
    if current == -1:
        # current version was unresolved — only show latest
        return f"[red]? → {latest}[/]" if latest > 0 else "?"
    if current == 0 and latest == 0:
        return "—"
    if current > 0 and latest == 0:
        return f"[red]{current}[/] → [green]0 ✓[/]"
    if current > 0 and latest < current:
        return f"[red]{current}[/] → [yellow]{latest}[/]"
    if current > 0:
        return f"[red]{current}[/]"
    return f"[yellow]→ {latest}[/]"  # new CVE appeared in latest


def _format_table(results: list[FrictionResult]) -> None:
    table = Table(title="scori — friction scores")
    table.add_column("Package")
    table.add_column("Current")
    table.add_column("Latest")
    table.add_column("Jump")
    table.add_column("Score", justify="right")
    table.add_column("Label")
    table.add_column("CVEs", justify="center")
    color_map = {
        "Low": "green",
        "Medium": "yellow",
        "High": "orange1",
        "Critical": "red",
    }
    for r in results:
        color = color_map.get(r["label"], "white")
        table.add_row(
            r["name"],
            r["current_version"],
            r["latest_version"],
            r["version_jump"],
            f"[{color}]{r['score']}[/]",
            f"[{color}]{r['label']}[/]",
            _fmt_cves(r["cve_current"], r["cve_latest"]),
        )
    console.print(table)


def _format_html(results: list[FrictionResult]) -> str:
    rows = "\n".join(
        f"<tr><td>{r['name']}</td><td>{r['current_version']}</td>"
        f"<td>{r['latest_version']}</td><td>{r['version_jump']}</td>"
        f"<td>{r['score']}</td><td>{r['label']}</td>"
        f"<td>{r['cve_current']} → {r['cve_latest']}</td></tr>"
        for r in results
    )
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>scori report</title></head><body>"
        "<h1>scori — friction scores</h1>"
        "<table border='1' cellpadding='6' cellspacing='0'>"
        "<thead><tr><th>Package</th><th>Current</th><th>Latest</th>"
        "<th>Jump</th><th>Score</th><th>Label</th><th>CVEs</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></body></html>"
    )


def _cmd_friction(args: argparse.Namespace) -> int:
    deps = scan(args.path)
    project_root = Path(args.path)
    results: list[FrictionResult] = [compute(d, project_root=project_root) for d in deps]
    if args.format == "json":
        print(jsonlib.dumps(results, indent=2))
    elif args.format == "html":
        out = Path(args.path) / "scori-report.html"
        out.write_text(_format_html(results), encoding="utf-8")
        console.print(f"[green]HTML report written to {out}[/]")
    else:
        _format_table(results)
    if args.ci:
        over = [r for r in results if r["score"] > args.threshold]
        if over:
            names = ", ".join(r["name"] for r in over)
            console.print(
                f"[red]CI: {len(over)} dependenc{'y' if len(over) == 1 else 'ies'} "
                f"exceeded threshold {args.threshold}: {names}[/]"
            )
            return 1
        console.print(f"[green]CI: all dependencies within threshold {args.threshold}[/]")
    return 0


def _format_monitor_table(results: list[FrictionResult]) -> None:
    table = Table(title="scori — updates available")
    table.add_column("Package")
    table.add_column("Installed")
    table.add_column("Latest")
    table.add_column("Jump")
    table.add_column("Score", justify="right")
    table.add_column("Label")
    table.add_column("CVEs", justify="center")
    color_map = {
        "Low": "green",
        "Medium": "yellow",
        "High": "orange1",
        "Critical": "red",
    }
    for r in results:
        color = color_map.get(r["label"], "white")
        cve_cell = _fmt_cves(r["cve_current"], r["cve_latest"])
        # Flag packages where updating fixes CVEs with a star marker
        fixes_cves = r["cve_current"] > 0 and r["cve_latest"] < r["cve_current"]
        name_cell = f"[bold]{r['name']}[/] [yellow]★[/]" if fixes_cves else r["name"]
        table.add_row(
            name_cell,
            r["current_version"],
            r["latest_version"],
            r["version_jump"],
            f"[{color}]{r['score']}[/]",
            f"[{color}]{r['label']}[/]",
            cve_cell,
        )
    console.print(table)
    if any(r["cve_current"] > 0 and r["cve_latest"] < r["cve_current"] for r in results):
        console.print("[dim]★ updating this package fixes known CVEs[/]")


def _cmd_monitor(args: argparse.Namespace) -> int:
    first = True
    while True:
        if not first:
            console.clear()
        first = False

        deps = scan(args.path)
        project_root = Path(args.path)
        all_results: list[FrictionResult] = [
            compute(d, project_root=project_root) for d in deps
        ]

        updates = [
            r for r in all_results
            if r["current_version"] != r["latest_version"]
            and r["current_version"] != "0.0.0"
        ]
        updates.sort(key=lambda r: r["score"], reverse=True)

        if updates:
            _format_monitor_table(updates)
        else:
            console.print("[green]All dependencies are up to date.[/]")

        if not args.watch:
            break

        console.print(
            f"\n[dim]Checking every {args.interval}s — Ctrl+C to stop.[/]"
        )
        try:
            time.sleep(args.interval)
        except KeyboardInterrupt:
            break

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scori")
    parser.add_argument("--version", action="version", version=f"scori {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="List dependencies of the target project")
    p_scan.add_argument("--path", default=".", help="Path to the target project")
    p_scan.set_defaults(func=_cmd_scan)

    p_fric = sub.add_parser("friction", help="Compute friction score per dependency")
    p_fric.add_argument("--path", default=".", help="Path to the target project")
    p_fric.add_argument(
        "--format", choices=["json", "table", "html"], default="table"
    )
    p_fric.add_argument(
        "--ci", action="store_true",
        help="Exit with code 1 if any dependency exceeds the threshold",
    )
    p_fric.add_argument(
        "--threshold", type=int, default=75, metavar="SCORE",
        help="Score threshold for --ci (default: 75)",
    )
    p_fric.set_defaults(func=_cmd_friction)

    p_mon = sub.add_parser(
        "monitor", help="Show dependencies with available updates, sorted by friction"
    )
    p_mon.add_argument("--path", default=".", help="Path to the target project")
    p_mon.add_argument(
        "--watch", action="store_true",
        help="Poll continuously for new releases",
    )
    p_mon.add_argument(
        "--interval", type=int, default=300, metavar="SECONDS",
        help="Polling interval in seconds when --watch is active (default: 300)",
    )
    p_mon.set_defaults(func=_cmd_monitor)

    # TODO v0.2: sub.add_parser("update"), sub.add_parser("report")

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
