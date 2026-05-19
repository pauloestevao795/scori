"""scori CLI.

Available commands:
    scori scan --path .
    scori friction --path . [--format json|table|html|markdown|cyclonedx]
    scori monitor --path . [--watch [--interval N]]
    scori update --path . [--dry-run | --apply [--max-friction LABEL] | --rollback]
    scori report --path . [--format html|json] [--output FILE] [--ci [--threshold N]]
    scori history --path . [--limit N]
    scori order --path . [--stub-diff]
    scori fix --path . [--apply] [--max-friction LABEL]
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
from ._types import Dependency, FrictionResult
from .config import ScoriConfig
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from .friction import compute
from .history import compute_trends, load_history, save_snapshot
from .lockfile import detect_update_conflicts, load_transitive_counts
from .scanner import scan
from .summarise import summarise

console = Console()


def _compute_all(
    deps: list[Dependency],
    project_root: Path,
    stub_diff: bool = False,
    lang: str = "python",
) -> list[FrictionResult]:
    runner: Callable[[Dependency], FrictionResult]
    if lang == "npm":
        from .npm import compute_npm, load_transitive_counts_npm
        transitive = load_transitive_counts_npm(project_root)

        def _run_npm(d: Dependency) -> FrictionResult:
            return compute_npm(
                d,
                transitive_affected=transitive.get(d["name"].lower(), 0),
                project_root=project_root,
            )

        runner = _run_npm
    elif lang == "auto":
        from .npm import compute_npm, load_transitive_counts_npm
        transitive_py = load_transitive_counts(project_root)
        transitive_npm = load_transitive_counts_npm(project_root)

        def _run_auto(d: Dependency) -> FrictionResult:
            if d["source_file"] == "package.json":
                return compute_npm(
                    d,
                    transitive_affected=transitive_npm.get(d["name"].lower(), 0),
                    project_root=project_root,
                )
            return compute(
                d,
                transitive_affected=transitive_py.get(d["name"].lower(), 0),
                project_root=project_root,
                stub_diff=stub_diff,
            )

        runner = _run_auto
    else:
        transitive = load_transitive_counts(project_root)

        def _run_py(d: Dependency) -> FrictionResult:
            return compute(
                d,
                transitive_affected=transitive.get(d["name"].lower(), 0),
                project_root=project_root,
                stub_diff=stub_diff,
            )

        runner = _run_py

    workers = min(16, len(deps)) if deps else 1
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(runner, deps))


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
    console.print("[bold yellow]⚠ Unresolved vulns — consider these alternatives:[/]")
    for r in flagged:
        alts = ", ".join(f"[cyan]{a}[/]" for a in r["alternatives"])
        n = r["cve_current"]
        console.print(
            f"  [red]{r['name']}[/] "
            f"([red]{n} vuln{'s' if n != 1 else ''}[/], "
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
    table.add_column("Vuln", justify="center")
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


def _fmt_cves_plain(current: int, latest: int) -> str:
    if current == -1:
        return f"? → {latest}" if latest > 0 else "?"
    if current == 0 and latest == 0:
        return "—"
    if current > 0 and latest == 0:
        return f"{current} → 0 ✓"
    if current > 0 and latest < current:
        return f"{current} → {latest}"
    if current > 0:
        return str(current)
    return f"→ {latest}"


def _format_markdown(results: list[FrictionResult], threshold: int = 75) -> str:
    label_emoji = {"Low": "🟢", "Medium": "🟡", "High": "🟠", "Critical": "🔴"}
    over = [r for r in results if r["score"] > threshold]
    header = "## scori — dependency friction scores\n\n"
    if over:
        names = ", ".join(f"`{r['name']}`" for r in over)
        header += (
            f"> ⚠️ **{len(over)} {'dependency' if len(over) == 1 else 'dependencies'} "
            f"exceeded threshold {threshold}:** {names}\n\n"
        )
    rows = [
        "| Package | Current | Latest | Jump | Score | Label | Vuln |",
        "|---------|---------|--------|------|------:|-------|:----:|",
    ]
    for r in results:
        emoji = label_emoji.get(r["label"], "⚪")
        cve_cell = _fmt_cves_plain(r["cve_current"], r["cve_latest"])
        rows.append(
            f"| {r['name']} | {r['current_version']} | {r['latest_version']} "
            f"| {r['version_jump']} | {r['score']} "
            f"| {emoji} {r['label']} | {cve_cell} |"
        )
    alts = [r for r in results if r["alternatives"]]
    footer = ""
    if alts:
        footer = "\n\n### ⚠️ Unresolved vulns — consider alternatives\n\n"
        for r in alts:
            footer += f"- **{r['name']}** → {', '.join(r['alternatives'])}\n"
    return header + "\n".join(rows) + footer


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
        "<th>Jump</th><th>Score</th><th>Label</th><th>Vuln</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></body></html>"
    )


def _summarise_result(r: FrictionResult) -> str:
    """Fetch release text for a result and return an LLM summary."""
    from .friction import _gather

    data = _gather(r["name"])
    releases: list[dict] = data.get("releases", [])  # type: ignore[type-arg]
    changelog: str = data.get("changelog", "")
    release_text = "\n".join(rel.get("body", "") for rel in releases if rel.get("body"))
    text = f"{release_text}\n{changelog}"
    return summarise(r["name"], r["current_version"], r["latest_version"], text)


def _cmd_friction(args: argparse.Namespace) -> int:
    cfg = ScoriConfig.load(Path(args.path))
    threshold = args.threshold if args.threshold != 75 else cfg.threshold
    lang: str = getattr(args, "lang", "python")

    if lang == "npm":
        from .npm import scan_npm
        raw_deps = scan_npm(args.path)
    elif lang == "auto":
        from .scanner import scan_all
        raw_deps = scan_all(args.path)
    else:
        raw_deps = scan(args.path)
    deps = [d for d in raw_deps if d["name"].lower() not in cfg.ignore]
    project_root = Path(args.path)
    results = _compute_all(deps, project_root, stub_diff=args.stub_diff, lang=lang)

    save_snapshot(project_root, results)

    if args.format == "json":
        print(jsonlib.dumps(results, indent=2))
    elif args.format == "cyclonedx":
        from .sbom import to_cyclonedx

        print(jsonlib.dumps(to_cyclonedx(results), indent=2))
    elif args.format == "html":
        out = Path(args.path) / "scori-report.html"
        out.write_text(_format_html(results), encoding="utf-8")
        console.print(f"[green]HTML report written to {out}[/]")
    elif args.format == "markdown":
        print(_format_markdown(results, threshold=threshold))
    else:
        _format_table(results)
        _print_alternatives(results)
        if args.summarise:
            flagged = [r for r in results if r["label"] in ("High", "Critical")]
            if flagged:
                console.print()
                console.print("[bold]LLM update summaries:[/]")
                for r in flagged:
                    summary = _summarise_result(r)
                    if summary:
                        console.print(f"  [bold]{r['name']}[/]: [dim]{summary}[/]")
    if args.ci:
        over = [r for r in results if r["score"] > threshold]
        if over:
            names = ", ".join(r["name"] for r in over)
            console.print(
                f"[red]CI: {len(over)} dependenc{'y' if len(over) == 1 else 'ies'} "
                f"exceeded threshold {threshold}: {names}[/]"
            )
            return 1
        console.print(f"[green]CI: all dependencies within threshold {threshold}[/]")
    return 0


def _format_monitor_table(results: list[FrictionResult]) -> None:
    table = Table(title="scori — updates available")
    table.add_column("Package")
    table.add_column("Installed")
    table.add_column("Latest")
    table.add_column("Jump")
    table.add_column("Score", justify="right")
    table.add_column("Label")
    table.add_column("Vuln", justify="center")
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
        console.print("[dim]★ updating this package fixes known vulns[/]")


def _cmd_monitor(args: argparse.Namespace) -> int:
    cfg = ScoriConfig.load(Path(args.path))
    lang: str = getattr(args, "lang", "python")
    first = True
    while True:
        if not first:
            console.clear()
        first = False

        if lang == "npm":
            from .npm import scan_npm
            raw_deps = scan_npm(args.path)
        elif lang == "auto":
            from .scanner import scan_all
            raw_deps = scan_all(args.path)
        else:
            raw_deps = scan(args.path)
        deps = [d for d in raw_deps if d["name"].lower() not in cfg.ignore]
        project_root = Path(args.path)
        all_results = _compute_all(deps, project_root, lang=lang)

        updates = [
            r
            for r in all_results
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

        console.print(f"\n[dim]Checking every {args.interval}s — Ctrl+C to stop.[/]")
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
    return f"→ {latest}"


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
            return "".join('<span class="alt-badge">' + a + "</span>" for a in alts)

        alt_rows = "".join(
            '<div class="alt-row">'
            '<span class="alt-pkg">' + r["name"] + "</span>"
            '<span style="color:#8b949e;font-size:.82rem">'
            + str(r["cve_current"])
            + " CVE(s) — not fixed in latest</span>"
            '<span style="flex:1"></span>' + _alt_badges(r["alternatives"]) + "</div>\n"
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
<th>Jump</th><th>Score</th><th>Label</th><th>Vuln</th><th>Recommendation</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>
{alts_section}
</body>
</html>"""


def _cmd_report(args: argparse.Namespace) -> int:
    cfg = ScoriConfig.load(Path(args.path))
    threshold = args.threshold if args.threshold != 75 else cfg.threshold

    deps = scan(args.path)
    deps = [d for d in deps if d["name"].lower() not in cfg.ignore]
    project_root = Path(args.path)
    results = _compute_all(deps, project_root)
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
        over = [r for r in results if r["score"] > threshold]
        if over:
            names = ", ".join(r["name"] for r in over)
            console.print(
                f"[red]CI: {len(over)} "
                f"dependenc{'y' if len(over) == 1 else 'ies'} "
                f"exceeded threshold {threshold}: {names}[/]"
            )
            return 1
        console.print(f"[green]CI: all dependencies within threshold {threshold}[/]")
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
        r'^(\s*["\']?)(' + pkg_pat + r")(\[.*?\])?(\s*)"
        r'(==|>=|~=|!=|<=|>|<)([^\s,;"\'\\]+)',
        line,
        re.IGNORECASE,
    )
    if not m:
        return None
    prefix = line[: m.start(5)]  # everything before the operator
    suffix = line[m.end() :]  # everything after the version string
    return f"{prefix}=={new_version}{suffix}"


# Maps user-supplied source_file names to hardcoded safe literals so that
# taint from remote data never reaches path construction.
_SAFE_MANIFEST_NAMES: dict[str, str] = {
    "requirements.txt": "requirements.txt",
    "requirements-dev.txt": "requirements-dev.txt",
    "requirements-test.txt": "requirements-test.txt",
    "pyproject.toml": "pyproject.toml",
    "setup.cfg": "setup.cfg",
}


def _safe_manifest_path(project_root: Path, source_file: str) -> Path | None:
    """Return the manifest path using a hardcoded filename, or None if not allowed."""
    safe_name = _SAFE_MANIFEST_NAMES.get(Path(source_file).name)
    if safe_name is None:
        return None
    return project_root.resolve() / safe_name


def _backup_manifests(project_root: Path, source_files: set[str]) -> Path:
    backup_dir = project_root / _BACKUP_DIR
    backup_dir.mkdir(exist_ok=True)
    for sf in source_files:
        src = _safe_manifest_path(project_root, sf)
        if src is not None and src.exists():
            shutil.copy2(src, backup_dir / src.name)
    return backup_dir


def _cmd_update(args: argparse.Namespace) -> int:
    cfg = ScoriConfig.load(Path(args.path))
    project_root = Path(args.path).resolve()

    if args.rollback:
        backup_dir = project_root / _BACKUP_DIR
        if not backup_dir.exists():
            console.print("[red]No backup found. Run 'scori update --apply' first.[/]")
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
    deps = [d for d in deps if d["name"].lower() not in cfg.ignore]
    results = _compute_all(deps, project_root)

    max_score = (
        _LABEL_MAX_SCORE.get(args.max_friction.lower(), 100)
        if args.max_friction
        else 100
    )
    to_update = [
        r
        for r in results
        if r["current_version"] != r["latest_version"]
        and r["current_version"] != "0.0.0"
        and r["score"] <= max_score
    ]

    if not to_update:
        console.print("[green]No updates match the current filters.[/]")
        return 0

    dep_map = {d["name"].lower(): d["source_file"] for d in deps}
    color_map = {
        "Low": "green",
        "Medium": "yellow",
        "High": "orange1",
        "Critical": "red",
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
            "[dim]Dry run — no files modified. Use --apply to write changes.[/]"
        )
        return 0

    # Backup then apply
    source_files = {
        dep_map[r["name"].lower()] for r in to_update if r["name"].lower() in dep_map
    }
    backup_dir = _backup_manifests(project_root, source_files)
    console.print(f"[dim]Backup saved to {backup_dir}[/]")

    applied = 0
    for r in to_update:
        sf = dep_map.get(r["name"].lower())
        if not sf:
            continue
        manifest = _safe_manifest_path(project_root, sf)
        if manifest is None or not manifest.exists():
            continue
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


_TREND_COLOR: dict[str, str] = {
    "↑": "red",
    "↓": "green",
    "—": "dim",
    "↕": "yellow",
}


def _cmd_history(args: argparse.Namespace) -> int:
    project_root = Path(args.path)
    history = load_history(project_root, limit=args.limit)
    if not history:
        console.print("[dim]No history yet — run scori friction to start tracking[/]")
        return 0

    trends = compute_trends(history)

    # Collect all package names (preserve insertion order across entries)
    all_pkgs: list[str] = []
    seen: set[str] = set()
    for entry in history:
        for pkg in entry.get("scores", {}):
            if pkg not in seen:
                seen.add(pkg)
                all_pkgs.append(pkg)

    # Build date labels from timestamps
    date_labels = [
        datetime.fromtimestamp(e["ts"], tz=UTC).strftime("%m-%d") for e in history
    ]

    table = Table(title="scori — score history")
    table.add_column("Package", style="bold")
    for label in date_labels:
        table.add_column(label, justify="right")
    table.add_column("Trend", justify="center")

    color_map = {
        "Low": "green",
        "Medium": "yellow",
        "High": "orange1",
        "Critical": "red",
    }

    def _score_label(score: int) -> str:
        if score <= 25:
            return "Low"
        if score <= 50:
            return "Medium"
        if score <= 75:
            return "High"
        return "Critical"

    for pkg in all_pkgs:
        row: list[str] = [pkg]
        for entry in history:
            score = entry.get("scores", {}).get(pkg)
            if score is None:
                row.append("—")
            else:
                lbl = _score_label(score)
                color = color_map.get(lbl, "white")
                row.append(f"[{color}]{score}[/]")
        trend = trends.get(pkg, "—")
        trend_color = _TREND_COLOR.get(trend, "white")
        row.append(f"[{trend_color}]{trend}[/]")
        table.add_row(*row)

    console.print(table)
    return 0


def _cmd_order(args: argparse.Namespace) -> int:
    cfg = ScoriConfig.load(Path(args.path))
    deps = scan(args.path)
    deps = [d for d in deps if d["name"].lower() not in cfg.ignore]
    project_root = Path(args.path)
    results = _compute_all(
        deps, project_root, stub_diff=getattr(args, "stub_diff", False)
    )

    # Filter to only those with available updates
    updatable = [
        r
        for r in results
        if r["current_version"] != r["latest_version"]
        and r["current_version"] != "0.0.0"
    ]

    if not updatable:
        console.print("[green]All dependencies are up to date.[/]")
        return 0

    label_order = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

    def _sort_key(r: FrictionResult) -> tuple[int, int, int]:
        fixes_cves = int(r["cve_current"] > 0 and r["cve_latest"] < r["cve_current"])
        return (label_order.get(r["label"], 0), -fixes_cves, r["score"])

    updatable.sort(key=_sort_key)

    def _reason(r: FrictionResult) -> str:
        fixes_cves = r["cve_current"] > 0 and r["cve_latest"] < r["cve_current"]
        parts: list[str] = []
        if fixes_cves:
            n = r["cve_current"] - r["cve_latest"]
            parts.append(f"fixes {n} CVE{'s' if n != 1 else ''}")
        jump = r["version_jump"]
        if jump == "patch":
            parts.append("patch update, low risk")
        elif jump == "minor":
            parts.append("minor version jump — run tests")
        elif jump == "major":
            parts.append("major version jump — review changelog")
        if r["breaking_signals"]:
            parts.append("breaking signals detected")
        if r["yanked"]:
            parts.append("current version is yanked")
        return "; ".join(parts) if parts else r["label"].lower() + " friction"

    color_map = {
        "Low": "green",
        "Medium": "yellow",
        "High": "orange1",
        "Critical": "red",
    }

    table = Table(title="scori — suggested update order")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Package")
    table.add_column("Score", justify="right")
    table.add_column("Label")
    table.add_column("Reason")

    for i, r in enumerate(updatable, start=1):
        color = color_map.get(r["label"], "white")
        fixes_cves = r["cve_current"] > 0 and r["cve_latest"] < r["cve_current"]
        name_cell = f"{r['name']} [yellow]★[/]" if fixes_cves else r["name"]
        table.add_row(
            str(i),
            name_cell,
            f"[{color}]{r['score']}[/]",
            f"[{color}]{r['label']}[/]",
            _reason(r),
        )

    console.print(table)
    fixes_any = any(
        r["cve_current"] > 0 and r["cve_latest"] < r["cve_current"] for r in updatable
    )
    if fixes_any:
        console.print("[dim]★ updating this package fixes known vulns[/]")

    conflicts = detect_update_conflicts(project_root, [r["name"] for r in updatable])
    if conflicts:
        console.print()
        console.print("[bold yellow]⚠ Shared transitive dependencies detected:[/]")
        for c in conflicts:
            console.print(f"  [yellow]{c}[/]")
    return 0


def _cmd_fix(args: argparse.Namespace) -> int:
    from .fix import create_pr, current_branch

    cfg = ScoriConfig.load(Path(args.path))
    project_root = Path(args.path).resolve()

    deps = scan(args.path)
    deps = [d for d in deps if d["name"].lower() not in cfg.ignore]
    results = _compute_all(deps, project_root)

    max_score = (
        _LABEL_MAX_SCORE.get(args.max_friction.lower(), 100)
        if args.max_friction
        else 100
    )
    dep_map = {d["name"].lower(): d["source_file"] for d in deps}

    result_map = {r["name"].lower(): r for r in results}
    updatable = [
        (
            r["name"],
            r["current_version"],
            r["latest_version"],
            dep_map.get(r["name"].lower(), ""),
        )
        for r in results
        if r["current_version"] != r["latest_version"]
        and r["current_version"] != "0.0.0"
        and r["score"] <= max_score
    ]

    # Sort lowest friction first (safest updates in the PR)
    def _fix_sort_key(t: tuple[str, str, str, str]) -> int:
        e = result_map.get(t[0].lower())
        return e["score"] if e else 100

    updatable.sort(key=_fix_sort_key)

    if not updatable:
        console.print("[green]No updates to apply.[/]")
        return 0

    color_map = {
        "Low": "green",
        "Medium": "yellow",
        "High": "orange1",
        "Critical": "red",
    }
    table = Table(
        title="scori fix — proposed PR" + (" [dry run]" if not args.apply else "")
    )
    table.add_column("Package")
    table.add_column("Current → Latest")
    table.add_column("Score")
    table.add_column("File")
    for name, cur, lat, sf in updatable:
        r_entry = result_map.get(name.lower())
        label = r_entry["label"] if r_entry else ""
        color = color_map.get(str(label), "white")
        score: int | str = r_entry["score"] if r_entry else "?"
        table.add_row(
            name,
            f"{cur} → [bold]{lat}[/]",
            f"[{color}]{score} {label}[/]" if label else str(score),
            sf or "?",
        )
    console.print(table)

    dry_run = not args.apply
    if dry_run:
        console.print(
            "\n[dim]Dry run — no PR created. Use --apply to open a GitHub PR.[/]"
        )
        return 0

    try:
        base = current_branch(project_root)
        outcome = create_pr(
            project_root=project_root,
            updates=updatable,
            results=results,
            base_branch=base,
            dry_run=False,
        )
        pr_url = outcome.get("pr_url") or ""
        console.print(f"\n[green]PR created: {pr_url}[/]")
    except (ValueError, RuntimeError) as e:
        console.print(f"[red]Error: {e}[/]")
        return 1

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
        "--format",
        choices=["json", "table", "html", "markdown", "cyclonedx"],
        default="table",
    )
    p_fric.add_argument(
        "--ci",
        action="store_true",
        help="Exit with code 1 if any dependency exceeds the threshold",
    )
    p_fric.add_argument(
        "--threshold",
        type=int,
        default=75,
        metavar="SCORE",
        help="Score threshold for --ci (default: 75)",
    )
    p_fric.add_argument(
        "--summarise",
        action="store_true",
        help="Print LLM summaries for High/Critical dependencies (table format only)",
    )
    p_fric.add_argument(
        "--stub-diff",
        action="store_true",
        help="Download wheels and diff .pyi stubs for API removal signals (slow)",
    )
    p_fric.add_argument(
        "--lang",
        choices=["auto", "python", "npm"],
        default="auto",
        help="Dependency ecosystem — auto detects both Python and npm (default: auto)",
    )
    p_fric.set_defaults(func=_cmd_friction)

    p_mon = sub.add_parser(
        "monitor", help="Show dependencies with available updates, sorted by friction"
    )
    p_mon.add_argument("--path", default=".", help="Path to the target project")
    p_mon.add_argument(
        "--watch",
        action="store_true",
        help="Poll continuously for new releases",
    )
    p_mon.add_argument(
        "--interval",
        type=int,
        default=300,
        metavar="SECONDS",
        help="Polling interval in seconds when --watch is active (default: 300)",
    )
    p_mon.add_argument(
        "--lang",
        choices=["auto", "python", "npm"],
        default="auto",
        help="Dependency ecosystem — auto detects both Python and npm (default: auto)",
    )
    p_mon.set_defaults(func=_cmd_monitor)

    p_upd = sub.add_parser(
        "update", help="Update dependency versions in manifest files"
    )
    p_upd.add_argument("--path", default=".", help="Path to the target project")
    upd_mode = p_upd.add_mutually_exclusive_group()
    upd_mode.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would change without modifying files (default behaviour)",
    )
    upd_mode.add_argument(
        "--apply",
        action="store_true",
        help="Write updates to manifest files and create a backup",
    )
    upd_mode.add_argument(
        "--rollback",
        action="store_true",
        help="Restore manifest files from the last backup",
    )
    p_upd.add_argument(
        "--max-friction",
        metavar="LABEL",
        choices=["low", "medium", "high", "critical"],
        help="Only update deps at or below this label (low/medium/high/critical)",
    )
    p_upd.set_defaults(func=_cmd_update)

    p_rep = sub.add_parser("report", help="Generate a friction report (HTML or JSON)")
    p_rep.add_argument("--path", default=".", help="Path to the target project")
    p_rep.add_argument(
        "--format",
        choices=["html", "json"],
        default="html",
        help="Output format (default: html)",
    )
    p_rep.add_argument(
        "--output",
        metavar="FILE",
        help="Output file path (default: scori-report.html or stdout for json)",
    )
    p_rep.add_argument(
        "--ci",
        action="store_true",
        help="Exit with code 1 if any dependency exceeds the threshold",
    )
    p_rep.add_argument(
        "--threshold",
        type=int,
        default=75,
        metavar="SCORE",
        help="Score threshold for --ci (default: 75)",
    )
    p_rep.set_defaults(func=_cmd_report)

    p_hist = sub.add_parser(
        "history", help="Show friction score history for the project"
    )
    p_hist.add_argument("--path", default=".", help="Path to the target project")
    p_hist.add_argument(
        "--limit",
        type=int,
        default=10,
        metavar="N",
        help="Number of historical snapshots to show (default: 10)",
    )
    p_hist.set_defaults(func=_cmd_history)

    p_fix = sub.add_parser(
        "fix", help="Open a GitHub PR with recommended dependency updates"
    )
    p_fix.add_argument("--path", default=".", help="Path to the target project")
    p_fix.add_argument(
        "--apply",
        action="store_true",
        help="Create the PR (requires GITHUB_TOKEN). Default: dry run only.",
    )
    p_fix.add_argument(
        "--max-friction",
        metavar="LABEL",
        choices=["low", "medium", "high", "critical"],
        help="Only include deps at or below this label in the PR",
    )
    p_fix.set_defaults(func=_cmd_fix)

    p_ord = sub.add_parser(
        "order", help="Show a ranked update plan sorted by risk and CVE impact"
    )
    p_ord.add_argument("--path", default=".", help="Path to the target project")
    p_ord.add_argument(
        "--stub-diff",
        action="store_true",
        help="Download wheels and diff .pyi stubs for API removal signals (slow)",
    )
    p_ord.set_defaults(func=_cmd_order)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
