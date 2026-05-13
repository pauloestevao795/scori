# scori

**Software Composition Risk Intelligence** — *Know the cost before you update.*

[![PyPI](https://img.shields.io/pypi/v/scori.svg)](https://pypi.org/project/scori/)
[![Python](https://img.shields.io/pypi/pyversions/scori.svg)](https://pypi.org/project/scori/)
[![License](https://img.shields.io/pypi/l/scori.svg)](LICENSE)
[![CI](https://github.com/pauloestevao795/scori/actions/workflows/ci.yml/badge.svg)](https://github.com/pauloestevao795/scori/actions/workflows/ci.yml)

Free tools like `pip-audit`, OSV-Scanner, and Dependabot detect vulnerabilities and open update PRs — but none of them answer the question that matters: *is it worth updating this lib right now, or does the migration cost outweigh the risk of not doing it?* `scori` quantifies that friction as a single 0–100 score per dependency, using public data from PyPI, GitHub, and the OSV vulnerability database.

## Install

```bash
pip install scori
# or
uv add scori
```

## Usage

```bash
# Show friction scores for every dependency
scori friction --path .
scori friction --path . --format json > report.json
scori friction --path . --format html        # writes scori-report.html
scori friction --path . --format markdown    # markdown table (GitHub / PR comments)
scori friction --path . --ci                 # exit 1 if any score > 75
scori friction --path . --ci --threshold 50  # stricter gate
scori friction --path . --summarise          # LLM plain-language summary per update

# Show only dependencies with updates available, sorted by friction
scori monitor --path .
scori monitor --path . --watch               # re-check every 5 minutes
scori monitor --path . --watch --interval 60 # re-check every 60 s

# Preview and apply dependency version updates
scori update --path . --dry-run              # show what would change
scori update --path . --apply                # write changes + create backup
scori update --path . --apply --max-friction medium  # only Low/Medium deps
scori update --path . --rollback             # restore from last backup

# Generate a standalone report
scori report --path .                        # writes scori-report.html
scori report --path . --format json          # prints JSON to stdout
scori report --path . --output out.html      # custom output path
scori report --path . --ci --threshold 60    # exit 1 if any score > 60

# Score history and trends
scori history --path .                       # last 10 snapshots with ↑↓ trend per dep
scori history --path . --limit 20            # last 20 snapshots

# Recommended update order
scori order --path .                         # rank deps by update priority

# List all detected dependencies
scori scan --path .
```

Example output (`scori friction --format table`, with color indicators):

```text
                          scori — friction scores
┌───────────┬─────────┬─────────┬───────┬───────┬──────────┬─────────┐
│ Package   │ Current │ Latest  │ Jump  │ Score │ Label    │  Vuln   │
├───────────┼─────────┼─────────┼───────┼───────┼──────────┼─────────┤
│ django    │ 3.2.0   │ 5.1.0   │ major │  78   │ Critical │ 3 → 0 ✓ │
│ nltk      │ 3.8.1   │ 3.9.4   │ minor │  35   │ Medium   │ 9 → 0 ✓ │
│ requests  │ 2.31.0  │ 2.32.3  │ patch │   8   │ Low      │    —    │
└───────────┴─────────┴─────────┴───────┴───────┴──────────┴─────────┘
```

The **Vuln** column shows known vulnerabilities (CVE/CWE) in your current version
and whether they are fixed in the latest release:

- `9 → 0 ✓` — 9 vulns in current, all fixed in latest (prioritize this update)
- `3` — 3 vulns, still present in latest (update won't help with security)
- `—` — no known vulnerabilities in either version

When CWE IDs are present in OSV data, scori maps them to OWASP Top 10 2021
categories (e.g. `CWE-79` → `A03 Injection`).

`scori monitor` shows only the packages that have a newer release available,
sorted by friction score (highest first), and marks with ★ any package where
updating also fixes known CVEs.

When a package has CVEs that are **not fixed in the latest version**, scori
searches PyPI online for alternatives with 0 known vulnerabilities and suggests
them below the table:

```text
⚠ Unresolved CVEs — consider these alternatives:
  python-jose (3 CVEs, not fixed in latest) → joserfc, authlib
  requests    (1 CVE,  not fixed in latest) → httpx
```

Alternatives are discovered dynamically: scori extracts keywords from the
vulnerable package's PyPI metadata, searches for similar packages, and verifies
each candidate against the OSV database before suggesting it. No hardcoded list
— any package on PyPI is a potential alternative.

## How it works

The friction score is a weighted sum of six components (max 100):

| Component                           | Max weight | Logic                                              |
|-------------------------------------|------------|----------------------------------------------------|
| Semantic version jump               | 50         | patch=5, minor=25, major=50                        |
| Breaking signals in changelog       | 20         | +4 per keyword found in release notes or CHANGELOG |
| Affected transitive dependencies    | 15         | +3 per reverse dep (from `uv.lock`/`poetry.lock`)  |
| CVEs fixed by updating              | 15         | +3 per fixed CVE (CRITICAL CVEs count double)      |
| Months without updating in project  | 10         | +1 per month (max 10)                              |
| Current version yanked              | 5          | +5 if `yanked: true` in PyPI API                   |

Labels:

- 0–25 → **Low** → *Safe to update*
- 26–50 → **Medium** → *Update with tests*
- 51–75 → **High** → *Update in isolated branch*
- 76–100 → **Critical** → *Manual migration required*

CVE data is fetched from the [OSV database](https://osv.dev) (free, no auth required).
CVEs that are **fixed by updating** contribute up to +15 points to the
friction score. CRITICAL-severity CVEs (CVSS ≥ 9.0, as reported by the GitHub
Advisory Database) count double, so the most dangerous vulnerabilities push
the package higher in your update queue. CVEs that remain in the latest version
do not affect the score (updating won't help with those).

Transitive dependency counts are read directly from `uv.lock` or `poetry.lock`
when present — no more always-zero placeholder.

### Data sources

| Source | Data |
| --- | --- |
| `https://pypi.org/pypi/{pkg}/json` | Latest version, release dates, yanked status |
| `https://api.github.com/repos/{owner}/{repo}/releases` | Release notes for breaking signal detection |
| `https://raw.githubusercontent.com/…/CHANGELOG.md` | CHANGELOG for additional breaking signal scanning |
| `https://api.osv.dev/v1/query` | Known CVEs per version with severity |

Set `GITHUB_TOKEN` in your environment to raise the GitHub API rate limit from 60/h to 5000/h. PyPI and GitHub release data is cached in `~/.cache/scori/` for 1 hour. OSV results are cached in memory for the duration of a single run.

### Version resolution

For pinned dependencies (`fastapi==0.115.8`), the pinned version is used directly. For unpinned dependencies (`uvicorn` with no version), scori looks up the installed version in the project's local venv (`.venv/`, `venv/`, or `env/`) before falling back to `0.0.0`.

## GitHub Actions

Add scori to any workflow in one step:

```yaml
- uses: pauloestevao795/scori@v0.4.0
  with:
    threshold: '75'       # fail if any dep score exceeds this (default: 75)
    comment-pr: 'true'    # post friction table as a PR comment
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

Full example — gate PRs that touch dependency files:

```yaml
name: scori friction check
on:
  pull_request:
    paths:
      - 'requirements*.txt'
      - 'pyproject.toml'
      - 'setup.cfg'

jobs:
  friction:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: pauloestevao795/scori@v0.4.0
        with:
          threshold: '75'
          comment-pr: 'true'
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pauloestevao795/scori
    rev: v0.4.0
    hooks:
      - id: scori-friction
        args: [--threshold, '75']  # optional: override default threshold
```

The hook runs `scori friction --ci` and blocks the commit if any dependency
exceeds the threshold. It only fires when `requirements*.txt`, `pyproject.toml`,
or `setup.cfg` are staged.

## Configuration

Create `.scori.toml` at the project root to customize scori's behaviour:

```toml
[scori]
profile = "conservative"  # conservative (50) | balanced (75) | aggressive (90)
threshold = 60            # explicit threshold overrides profile default

[ignore]
packages = ["boto3", "some-internal-lib"]  # skip these deps entirely
```

## Roadmap

- **v0.6** — conda/pyenv version resolution, `.pyi` stub diff for API-change detection, dynamic README badge

## Contributing

PRs and issues are welcome. Local setup:

```bash
git clone https://github.com/pauloestevao795/scori
cd scori
uv sync --group dev
uv run pre-commit install
uv run pytest
```

## License

MIT
