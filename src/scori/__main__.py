"""scori CLI.

Available commands:
    scori scan --path .
    scori friction --path . [--format json|table|html] [--ci [--threshold N]]
    scori monitor --path . [--watch [--interval N]]
    scori update --path . [--dry-run | --apply [--max-friction LABEL] | --rollback]
    scori report --path . [--format html|json] [--output FILE] [--ci [--threshold N]]
"""

from __future__ import annotations

import argparse
import json as jsonlib
import re
import shutil
import sys
import time
from datetime import UTC, datetime
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


def _print_alternatives(results: list[FrictionResult]) -> None:
    flagged = [r for r in results if r["alternatives"]]
    if not flagged:
        return
    console.print()
    console.print("[bold yellow]⚠ Unresolved CVEs — consider these alternatives:[/]")
    for r in flagged:
        alts = ", ".join(f"[cyan]{a}[/]" for a in r["alternatives"])
        console.print(
            f"  [red]{r['name']}[/] "
            f"([red]{r['cve_current']} CVE{'s' if r['cve_current'] != 1 else ''}[/], "
            f"not fixed in latest) → {alts}"
        )


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
    results: list[FrictionResult] = [
        compute(d, project_root=project_root) for d in deps
    ]
    if args.format == "json":
        print(jsonlib.dumps(results, indent=2))
    elif args.format == "html":
        out = Path(args.path) / "scori-report.html"
        out.write_text(_format_html(results), encoding="utf-8")
        console.print(f"[green]HTML report written to {out}[/]")
    else:
        _format_table(results)
        _print_alternatives(results)
    if args.ci:
        over = [r for r in results if r["score"] > args.threshold]
        if over:
            names = ", ".join(r["name"] for r in over)
            console.print(
                f"[red]CI: {len(over)} dependenc{'y' if len(over) == 1 else 'ies'} "
                f"exceeded threshold {args.threshold}: {names}[/]"
            )
            return 1
        console.print(
            f"[green]CI: all dependencies within threshold {args.threshold}[/]"
        )
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
    fixes_any = any(
        r["cve_current"] > 0 and r["cve_latest"] < r["cve_current"] for r in results
    )
    if fixes_any:
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
            _print_alternatives(updates)
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


_REPORT_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background: #0d1117; color: #e6edf3; padding: 2rem; }
h1 { font-size: 1.5rem; margin-bottom: .25rem; }
.meta { color: #8b949e; font-size: .85rem; margin-bottom: 2rem; }
.summary { display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
        padding: 1rem 1.5rem; min-width: 120px; text-align: center; }
.card .count { font-size: 2rem; font-weight: 700; }
.card .label { font-size: .8rem; color: #8b949e; margin-top: .25rem; }
.low .count { color: #3fb950; }
.medium .count { color: #d29922; }
.high .count { color: #f0883e; }
.critical .count { color: #f85149; }
.total .count { color: #e6edf3; }
table { width: 100%; border-collapse: collapse; background: #161b22;
        border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }
th { background: #21262d; color: #8b949e; font-size: .75rem; text-transform: uppercase;
     letter-spacing: .05em; padding: .75rem 1rem; text-align: left; }
td { padding: .75rem 1rem; border-top: 1px solid #21262d; font-size: .9rem; }
tr:hover td { background: #1c2128; }
.dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%;
       margin-right: .5rem; vertical-align: middle; }
.dot-low { background: #3fb950; }
.dot-medium { background: #d29922; }
.dot-high { background: #f0883e; }
.dot-critical { background: #f85149; }
.score-low { color: #3fb950; font-weight: 600; }
.score-medium { color: #d29922; font-weight: 600; }
.score-high { color: #f0883e; font-weight: 600; }
.score-critical { color: #f85149; font-weight: 600; }
.cve-fixed { color: #3fb950; }
.cve-bad { color: #f85149; }
.cve-none { color: #8b949e; }
.alts { margin-top: 2rem; }
.alts h2 { font-size: 1rem; color: #d29922; margin-bottom: .75rem; }
.alt-row { display: flex; align-items: baseline; gap: .5rem;
           padding: .4rem 0; border-bottom: 1px solid #21262d; font-size: .9rem; }
.alt-pkg { color: #f85149; font-weight: 600; min-width: 160px; }
.alt-badge { background: #1f2d1f; color: #3fb950; border: 1px solid #3fb950;
             border-radius: 4px; padding: .1rem .4rem; font-size: .78rem;
             white-space: nowrap; }
"""


def _fmt_cves_html(current: int, latest: int) -> str:
    if current == -1:
        return f'<span class="cve-none">? → {latest}</span>' if latest > 0 else "?"
    if current == 0 and latest == 0:
        return '<span class="cve-none">—</span>'
    if current > 0 and latest == 0:
        fixed = '<span class="cve-fixed">0 ✓</span>'
        return f'<span class="cve-bad">{current}</span> → {fixed}'
    if current > 0 and latest < current:
        return f'<span class="cve-bad">{current}</span> → {latest}'
    if current > 0:
        return f'<span class="cve-bad">{current}</span>'
    return f'→ {latest}'


def _build_rich_html(results: list[FrictionResult], path: str) -> str:
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    counts: dict[str, int] = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for r in results:
        counts[r["label"]] = counts.get(r["label"], 0) + 1

    summary_cards = "".join(
        f'<div class="card {label.lower()}">'
        f'<div class="count">{counts[label]}</div>'
        f'<div class="label">{label}</div></div>'
        for label in ("Low", "Medium", "High", "Critical")
    )
    summary_cards += (
        f'<div class="card total">'
        f'<div class="count">{len(results)}</div>'
        f'<div class="label">Total</div></div>'
    )

    rows = ""
    for r in results:
        lbl = r["label"].lower()
        rows += (
            f"<tr>"
            f'<td><span class="dot dot-{lbl}"></span>{r["name"]}</td>'
            f"<td>{r['current_version']}</td>"
            f"<td>{r['latest_version']}</td>"
            f"<td>{r['version_jump']}</td>"
            f'<td class="score-{lbl}">{r["score"]}</td>'
            f'<td class="score-{lbl}">{r["label"]}</td>'
            f"<td>{_fmt_cves_html(r['cve_current'], r['cve_latest'])}</td>"
            f"<td>{r['recommendation']}</td>"
            f"</tr>\n"
        )

    flagged = [r for r in results if r["alternatives"]]
    alts_section = ""
    if flagged:
        def _alt_badges(alts: list[str]) -> str:
            return "".join(
                '<span class="alt-badge">' + a + "</span>" for a in alts
            )

        alt_rows = "".join(
            '<div class="alt-row">'
            '<span class="alt-pkg">' + r["name"] + "</span>"
            '<span style="color:#8b949e;font-size:.82rem">'
            + str(r["cve_current"])
            + " CVE(s) — not fixed in latest</span>"
            '<span style="flex:1"></span>'
            + _alt_badges(r["alternatives"])
            + "</div>\n"
            for r in flagged
        )
        alts_section = (
            f'<div class="alts">'
            f"<h2>⚠ Unresolved CVEs — consider these alternatives</h2>"
            f"{alt_rows}</div>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>scori report — {path}</title>
<style>{_REPORT_CSS}</style>
</head>
<body>
<h1>scori — friction report</h1>
<p class="meta">Project: <strong>{path}</strong> &nbsp;·&nbsp; Generated: {now}</p>
<div class="summary">{summary_cards}</div>
<table>
<thead><tr>
<th>Package</th><th>Current</th><th>Latest</th>
<th>Jump</th><th>Score</th><th>Label</th><th>CVEs</th><th>Recommendation</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>
{alts_section}
</body>
</html>"""


def _cmd_report(args: argparse.Namespace) -> int:
    deps = scan(args.path)
    project_root = Path(args.path)
    results: list[FrictionResult] = [
        compute(d, project_root=project_root) for d in deps
    ]
    results.sort(key=lambda r: r["score"], reverse=True)

    if args.format == "json":
        content = jsonlib.dumps(results, indent=2)
        if args.output:
            Path(args.output).write_text(content, encoding="utf-8")
            console.print(f"[green]JSON report written to {args.output}[/]")
        else:
            print(content)
    else:
        html = _build_rich_html(results, args.path)
        out = args.output or "scori-report.html"
        Path(out).write_text(html, encoding="utf-8")
        console.print(f"[green]HTML report written to {out}[/]")

    if args.ci:
        over = [r for r in results if r["score"] > args.threshold]
        if over:
            names = ", ".join(r["name"] for r in over)
            console.print(
                f"[red]CI: {len(over)} "
                f"dependenc{'y' if len(over) == 1 else 'ies'} "
                f"exceeded threshold {args.threshold}: {names}[/]"
            )
            return 1
        console.print(
            f"[green]CI: all dependencies within threshold {args.threshold}[/]"
        )
    return 0


_LABEL_MAX_SCORE: dict[str, int] = {
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 100,
}
_BACKUP_DIR = ".scori-backup"


def _update_line(line: str, package: str, new_version: str) -> str | None:
    """Replace the version specifier for package in one manifest line.

    Returns the rewritten line, or None if the package is not on this line.
    Handles requirements.txt, pyproject.toml, and setup.cfg formats.
    """
    pkg_pat = re.sub(r"[-_.]", r"[-_.]", re.escape(package))
    m = re.match(
        r'^(\s*["\']?)(' + pkg_pat + r')(\[.*?\])?(\s*)'
        r'(==|>=|~=|!=|<=|>|<)([^\s,;"\'\\]+)',
        line,
        re.IGNORECASE,
    )
    if not m:
        return None
    prefix = line[:m.start(5)]   # everything before the operator
    suffix = line[m.end():]      # everything after the version string
    return f"{prefix}=={new_version}{suffix}"


def _backup_manifests(project_root: Path, source_files: set[str]) -> Path:
    backup_dir = project_root / _BACKUP_DIR
    backup_dir.mkdir(exist_ok=True)
    for sf in source_files:
        src = project_root / sf
        if src.exists():
            shutil.copy2(src, backup_dir / sf)
    return backup_dir


def _cmd_update(args: argparse.Namespace) -> int:
    project_root = Path(args.path).resolve()

    if args.rollback:
        backup_dir = project_root / _BACKUP_DIR
        if not backup_dir.exists():
            console.print(
                "[red]No backup found. Run 'scori update --apply' first.[/]"
            )
            return 1
        restored = [f for f in backup_dir.iterdir() if f.is_file()]
        if not restored:
            console.print("[red]Backup directory is empty.[/]")
            return 1
        for f in restored:
            shutil.copy2(f, project_root / f.name)
            console.print(f"[green]Restored {f.name}[/]")
        console.print("[green]Rollback complete.[/]")
        return 0

    deps = scan(args.path)
    results: list[FrictionResult] = [
        compute(d, project_root=project_root) for d in deps
    ]

    max_score = (
        _LABEL_MAX_SCORE.get(args.max_friction.lower(), 100)
        if args.max_friction
        else 100
    )
    to_update = [
        r for r in results
        if r["current_version"] != r["latest_version"]
        and r["current_version"] != "0.0.0"
        and r["score"] <= max_score
    ]

    if not to_update:
        console.print("[green]No updates match the current filters.[/]")
        return 0

    dep_map = {d["name"].lower(): d["source_file"] for d in deps}
    color_map = {
        "Low": "green", "Medium": "yellow",
        "High": "orange1", "Critical": "red",
    }

    mode = "dry run" if args.dry_run else "pending"
    table = Table(title=f"scori update — {len(to_update)} update(s) [{mode}]")
    table.add_column("Package")
    table.add_column("Current → Latest")
    table.add_column("Score")
    table.add_column("File")
    for r in to_update:
        color = color_map.get(r["label"], "white")
        table.add_row(
            r["name"],
            f"{r['current_version']} → [bold]{r['latest_version']}[/]",
            f"[{color}]{r['score']} {r['label']}[/]",
            dep_map.get(r["name"].lower(), "?"),
        )
    console.print(table)

    if args.dry_run or not args.apply:
        console.print(
            "[dim]Dry run — no files modified. "
            "Use --apply to write changes.[/]"
        )
        return 0

    # Backup then apply
    source_files = {
        dep_map[r["name"].lower()]
        for r in to_update
        if r["name"].lower() in dep_map
    }
    backup_dir = _backup_manifests(project_root, source_files)
    console.print(f"[dim]Backup saved to {backup_dir}[/]")

    applied = 0
    for r in to_update:
        sf = dep_map.get(r["name"].lower())
        if not sf:
            continue
        manifest = project_root / sf
        lines = manifest.read_text(encoding="utf-8").splitlines(keepends=True)
        for i, line in enumerate(lines):
            new_line = _update_line(line, r["name"], r["latest_version"])
            if new_line is not None:
                lines[i] = new_line
                applied += 1
                break
        manifest.write_text("".join(lines), encoding="utf-8")

    noun = "dependency" if applied == 1 else "dependencies"
    console.print(f"[green]Updated {applied} {noun}.[/]")
    console.print("[dim]To revert: scori update --rollback[/]")
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

    p_upd = sub.add_parser(
        "update", help="Update dependency versions in manifest files"
    )
    p_upd.add_argument("--path", default=".", help="Path to the target project")
    upd_mode = p_upd.add_mutually_exclusive_group()
    upd_mode.add_argument(
        "--dry-run", action="store_true",
        help="Show what would change without modifying files (default behaviour)",
    )
    upd_mode.add_argument(
        "--apply", action="store_true",
        help="Write updates to manifest files and create a backup",
    )
    upd_mode.add_argument(
        "--rollback", action="store_true",
        help="Restore manifest files from the last backup",
    )
    p_upd.add_argument(
        "--max-friction",
        metavar="LABEL",
        choices=["low", "medium", "high", "critical"],
        help="Only update deps at or below this label (low/medium/high/critical)",
    )
    p_upd.set_defaults(func=_cmd_update)

    p_rep = sub.add_parser(
        "report", help="Generate a friction report (HTML or JSON)"
    )
    p_rep.add_argument("--path", default=".", help="Path to the target project")
    p_rep.add_argument(
        "--format", choices=["html", "json"], default="html",
        help="Output format (default: html)",
    )
    p_rep.add_argument(
        "--output", metavar="FILE",
        help="Output file path (default: scori-report.html or stdout for json)",
    )
    p_rep.add_argument(
        "--ci", action="store_true",
        help="Exit with code 1 if any dependency exceeds the threshold",
    )
    p_rep.add_argument(
        "--threshold", type=int, default=75, metavar="SCORE",
        help="Score threshold for --ci (default: 75)",
    )
    p_rep.set_defaults(func=_cmd_report)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
