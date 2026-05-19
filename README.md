# scori

**Software Composition Risk Intelligence** — *Know the cost before you update.*

[![PyPI](https://img.shields.io/pypi/v/scori.svg)](https://pypi.org/project/scori/)
[![Python](https://img.shields.io/pypi/pyversions/scori.svg)](https://pypi.org/project/scori/)
[![License](https://img.shields.io/pypi/l/scori.svg)](LICENSE)
[![CI](https://github.com/pauloestevao795/scori/actions/workflows/ci.yml/badge.svg)](https://github.com/pauloestevao795/scori/actions/workflows/ci.yml)
[![friction](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/pauloestevao795/scori/main/badge.json)](https://github.com/pauloestevao795/scori)

Free tools like `pip-audit`, OSV-Scanner, and Dependabot detect vulnerabilities and open update PRs — but none of them answer the question that matters: *is it worth updating this lib right now, or does the migration cost outweigh the risk of not doing it?* `scori` quantifies that friction as a single 0–100 score per dependency, using public data from PyPI, npm, GitHub, and the OSV vulnerability database.

Supports **Python**, **Node.js**, **Go**, and **Rust** projects — including monorepos with any combination.

## Install

```bash
pip install scori
# or
uv add scori
```

## Usage

### Friction scores

```bash
# Auto-detects Python and npm manifests — works from any project root
scori friction --path .

# Output formats
scori friction --path . --format json > report.json
scori friction --path . --format cyclonedx > sbom.cdx.json  # CycloneDX 1.5 SBOM
scori friction --path . --format html                        # writes scori-report.html
scori friction --path . --format markdown                    # GitHub / PR comments

# CI gate
scori friction --path . --ci                 # exit 1 if any score > 75
scori friction --path . --ci --threshold 50  # stricter gate

# Extra signals
scori friction --path . --summarise          # LLM plain-language summary per update
scori friction --path . --stub-diff          # diff .pyi stubs for API removal signals (slow)

# Restrict to one ecosystem when needed
scori friction --path . --lang python
scori friction --path . --lang npm
scori friction --path . --lang go
scori friction --path . --lang rust
```

### Monitor, update, and fix

```bash
# Show only deps with updates available, sorted by friction
scori monitor --path .
scori monitor --path . --watch               # re-check every 5 minutes
scori monitor --path . --watch --interval 60

# Preview and apply version updates
scori update --path . --dry-run
scori update --path . --apply
scori update --path . --apply --max-friction medium
scori update --path . --rollback

# Generate a standalone report
scori report --path .
scori report --path . --format json
scori report --path . --output out.html
scori report --path . --ci --threshold 60

# Score history and trends
scori history --path .
scori history --path . --limit 20

# Recommended update order with conflict detection
scori order --path .
scori order --path . --stub-diff

# Open a GitHub PR with the recommended updates (requires GITHUB_TOKEN)
scori fix --path .
scori fix --path . --apply
scori fix --path . --apply --max-friction low

# List all detected dependencies
scori scan --path .
```

### Supported manifest formats

| Ecosystem | Manifests | Lockfiles |
| --- | --- | --- |
| **Python** | `requirements*.txt`, `pyproject.toml`, `setup.cfg`, `Pipfile`, `environment.yml`, `conda.yml` | `uv.lock`, `poetry.lock` |
| **Node.js** | `package.json` | `package-lock.json` (v1/v2/v3), `yarn.lock`, `pnpm-lock.yaml` |
| **Go** | `go.mod` | `go.sum` |
| **Rust** | `Cargo.toml` | `Cargo.lock` (v1/v2/v3) |

### Polyglot monorepos

Running `scori friction --path .` from a project root scores all supported ecosystems in one table — no flags needed:

```text
my-project/
  back/     ← pyproject.toml, uv.lock
  front/    ← package.json, package-lock.json
  service/  ← go.mod, go.sum
  agent/    ← Cargo.toml, Cargo.lock
```

```bash
cd my-project
scori friction --path .   # Python + npm + Go + Rust deps, single table
```

### Example output

```text
                          scori — friction scores
┌──────────────┬─────────┬─────────┬───────┬───────┬──────────┬─────────┐
│ Package      │ Current │ Latest  │ Jump  │ Score │ Label    │  Vuln   │
├──────────────┼─────────┼─────────┼───────┼───────┼──────────┼─────────┤
│ django       │ 3.2.0   │ 5.1.0   │ major │  78   │ Critical │ 3 → 0 ✓ │
│ lodash       │ 4.17.20 │ 4.17.21 │ patch │  12   │ Low      │ 1 → 0 ✓ │
│ nltk         │ 3.8.1   │ 3.9.4   │ minor │  35   │ Medium   │ 9 → 0 ✓ │
│ requests     │ 2.31.0  │ 2.32.3  │ patch │   8   │ Low      │    —    │
└──────────────┴─────────┴─────────┴───────┴───────┴──────────┴─────────┘
```

The **Vuln** column shows known vulnerabilities in your current version and whether they are fixed in the latest release:

- `9 → 0 ✓` — 9 vulns in current, all fixed in latest (prioritize this update)
- `3` — 3 vulns, still present in latest (updating won't help)
- `—` — no known vulnerabilities in either version

When CWE IDs are present in OSV data, scori maps them to OWASP Top 10 2021 categories (e.g. `CWE-79` → `A03 Injection`).

`scori monitor` shows only packages with a newer release available, sorted by friction score (highest first), and marks with ★ any package where updating also fixes known CVEs.

When a package has CVEs **not fixed in the latest version**, scori searches for alternatives with 0 known vulnerabilities:

```text
⚠ Unresolved CVEs — consider these alternatives:
  python-jose (3 CVEs, not fixed in latest) → joserfc, authlib
  requests    (1 CVE,  not fixed in latest) → httpx
```

---

## How it works

The friction score is a weighted sum of six components (max 100):

| Component                           | Max weight | Logic                                              |
|-------------------------------------|------------|----------------------------------------------------|
| Semantic version jump               | 50         | patch=5, minor=25, major=50                        |
| Breaking signals in changelog       | 20         | +4 per keyword found in release notes or CHANGELOG |
| Affected transitive dependencies    | 15         | +3 per reverse dep (from lockfile graph)           |
| CVEs fixed by updating              | 15         | +3 per fixed CVE (CRITICAL CVEs count double)      |
| Months without updating in project  | 10         | +1 per month (max 10)                              |
| Current version yanked / deprecated | 5          | +5 if yanked (PyPI) or deprecated (npm)            |

Labels:

- 0–25 → **Low** → *Safe to update*
- 26–50 → **Medium** → *Update with tests*
- 51–75 → **High** → *Update in isolated branch*
- 76–100 → **Critical** → *Manual migration required*

CVE data is fetched from the [OSV database](https://osv.dev) (free, no auth required). CRITICAL-severity CVEs count double, so the most dangerous vulnerabilities push higher in the queue. CVEs that remain in the latest version do not affect the score.

Transitive dependency counts are read from `uv.lock`, `poetry.lock`, `package-lock.json`, or `Cargo.lock`.

### Data sources

| Source | Data |
| --- | --- |
| `https://pypi.org/pypi/{pkg}/json` | Latest version, release dates, yanked status |
| `https://registry.npmjs.org/{pkg}` | Latest version, publish dates, deprecated status |
| `https://proxy.golang.org/{module}/@latest` | Latest Go module version and publish time |
| `https://proxy.golang.org/{module}/@v/{version}.info` | Per-version publish timestamp for Go |
| `https://crates.io/api/v1/crates/{name}` | Latest version, publish dates, yanked status for Rust |
| `https://api.github.com/repos/{owner}/{repo}/releases` | Release notes for breaking signal detection |
| `https://raw.githubusercontent.com/…/CHANGELOG.md` | CHANGELOG for additional breaking signal scanning |
| `https://api.osv.dev/v1/query` | Known CVEs per version with severity (PyPI + npm + Go + crates.io + more) |

Set `GITHUB_TOKEN` to raise the GitHub API rate limit from 60/h to 5000/h. Registry and GitHub data is cached in `~/.cache/scori/` for 1 hour. OSV results are cached in memory per run.

### Version resolution

**Python**: pinned spec → local venv (`.venv/`, `venv/`, `env/`) → conda (`conda list --json`) → pyenv (`.python-version`) → fallback `0.0.0`.

**Node.js**: `package-lock.json` → `yarn.lock` → `pnpm-lock.yaml` → `node_modules/{name}/package.json` → spec lower bound → fallback `0.0.0`.

---

## Python API

Stable public API from version 1.0 — `FrictionResult`, `Dependency`, `compute()`, `scan()`, `scan_all()`, `compute_npm()`, `scan_npm()`, `compute_go()`, `scan_go()`, `compute_rust()`, and `scan_rust()` will not change in backwards-incompatible ways in 1.x releases.

```python
from scori import (
    compute, compute_npm, compute_go, compute_rust,
    scan, scan_npm, scan_go, scan_rust, scan_all,
    Dependency, FrictionResult,
)

# Polyglot scan — Python + npm + Go + Rust in one call
deps = scan_all("/path/to/project")

# Per-ecosystem scans
py_deps   = scan("/path/to/project")
npm_deps  = scan_npm("/path/to/project")
go_deps   = scan_go("/path/to/project")
rust_deps = scan_rust("/path/to/project")

# Score a Python dependency
result: FrictionResult = compute(Dependency(
    name="django",
    version_spec="==3.2.0",
    source_file="requirements.txt",
))

# Score an npm dependency
result = compute_npm(Dependency(
    name="lodash",
    version_spec="^4.17.20",
    source_file="package.json",
))

# Score a Go module
result = compute_go(Dependency(
    name="github.com/gin-gonic/gin",
    version_spec="v1.8.0",
    source_file="go.mod",
))

# Score a Rust crate
result = compute_rust(Dependency(
    name="serde",
    version_spec="1.0",
    source_file="Cargo.toml",
))

print(result["score"])           # e.g. 12
print(result["label"])           # "Low"
print(result["version_jump"])    # "patch"
print(result["recommendation"])
```

`FrictionResult` fields: `name`, `current_version`, `latest_version`, `score`, `label`, `version_jump`, `breaking_signals`, `transitive_affected`, `months_outdated`, `yanked`, `recommendation`, `cve_current`, `cve_latest`, `cwe_ids`, `alternatives`.

---

## GitHub Actions

```yaml
- uses: pauloestevao795/scori@v1.2.0
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
      - 'package.json'
      - 'package-lock.json'

jobs:
  friction:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: pauloestevao795/scori@v1.2.0
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
    rev: v1.2.0
    hooks:
      - id: scori-friction
        args: [--threshold, '75']  # optional: override default threshold
```

The hook runs `scori friction --ci` and blocks the commit if any dependency exceeds the threshold. It fires when `requirements*.txt`, `pyproject.toml`, `setup.cfg`, or `package.json` are staged.

---

## Configuration

Create `.scori.toml` at the project root to customize behaviour:

```toml
[scori]
profile = "conservative"  # conservative (50) | balanced (75) | aggressive (90)
threshold = 60            # explicit threshold overrides profile default

[ignore]
packages = ["boto3", "some-internal-lib"]  # skip these deps (applies to all ecosystems)
```

---

## Roadmap

- **v1.0 ✅** — stable API, `Pipfile`/`conda.yml` support, parallel HTTP fetch, integration tests
- **v1.1 ✅** — Node.js ecosystem (`package.json`, npm registry, OSV, all lockfile formats, polyglot auto-detection)
- **v1.2 ✅** — Go (`go.mod`/`go.sum`, proxy.golang.org) and Rust (`Cargo.toml`/`Cargo.lock`, crates.io) ecosystems
- **v1.3** — Java and C# / .NET ecosystems

See [ROADMAP.md](ROADMAP.md) for the full multi-ecosystem plan.

## Contributing

PRs and issues are welcome. Local setup:

```bash
git clone https://github.com/pauloestevao795/scori
cd scori
uv sync --group dev
uv run pre-commit install
uv run pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

## License

MIT
