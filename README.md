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
scori friction --path . --ci                 # exit 1 if any score > 75
scori friction --path . --ci --threshold 50  # stricter gate

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

# List all detected dependencies
scori scan --path .
```

Example output (`scori friction --format table`, with color indicators):

```text
                          scori — friction scores
┌───────────┬─────────┬─────────┬───────┬───────┬──────────┬─────────┐
│ Package   │ Current │ Latest  │ Jump  │ Score │ Label    │  CVEs   │
├───────────┼─────────┼─────────┼───────┼───────┼──────────┼─────────┤
│ django    │ 3.2.0   │ 5.1.0   │ major │  78   │ Critical │ 3 → 0 ✓ │
│ nltk      │ 3.8.1   │ 3.9.4   │ minor │  35   │ Medium   │ 9 → 0 ✓ │
│ requests  │ 2.31.0  │ 2.32.3  │ patch │   8   │ Low      │    —    │
└───────────┴─────────┴─────────┴───────┴───────┴──────────┴─────────┘
```

The **CVEs** column shows known vulnerabilities in your current version and
whether they are fixed in the latest release:

- `9 → 0 ✓` — 9 CVEs in current, all fixed in latest (prioritize this update)
- `3` — 3 CVEs, still present in latest (update won't help with security)
- `—` — no known vulnerabilities in either version

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

The friction score is a weighted sum of five components (max 100):

| Component                           | Max weight | Logic                               |
|-------------------------------------|------------|-------------------------------------|
| Semantic version jump               | 50         | patch=5, minor=25, major=50         |
| Breaking signals in changelog       | 20         | +4 per keyword found (max 20)       |
| Affected transitive dependencies    | 15         | +3 per transitive dep (max 15)      |
| CVEs fixed by updating              | 15         | +3 per fixed CVE (max 15)           |
| Months without updating in project  | 10         | +1 per month (max 10)               |
| Current version yanked              | 5          | +5 if `yanked: true` in PyPI API    |

Labels:

- 0–25 → **Low** → *Safe to update*
- 26–50 → **Medium** → *Update with tests*
- 51–75 → **High** → *Update in isolated branch*
- 76–100 → **Critical** → *Manual migration required*

CVE data is fetched from the [OSV database](https://osv.dev) (free, no auth required).
CVEs that are **fixed by updating** contribute up to +15 points to the
friction score — a dependency where updating resolves known vulnerabilities
will score higher, pushing it toward the top of your update queue. CVEs that
remain present in the latest version do not affect the score (updating won't
help with those).

### Data sources

| Source | Data |
| --- | --- |
| `https://pypi.org/pypi/{pkg}/json` | Latest version, release dates, yanked status |
| `https://api.github.com/repos/{owner}/{repo}/releases` | Release notes for breaking signal detection |
| `https://api.osv.dev/v1/query` | Known CVEs per version |

Set `GITHUB_TOKEN` in your environment to raise the GitHub API rate limit from 60/h to 5000/h. PyPI and GitHub release data is cached in `~/.cache/scori/` for 1 hour. OSV results are cached in memory for the duration of a single run.

### Version resolution

For pinned dependencies (`fastapi==0.115.8`), the pinned version is used directly. For unpinned dependencies (`uvicorn` with no version), scori looks up the installed version in the project's local venv (`.venv/`, `venv/`, or `env/`) before falling back to `0.0.0`.

## Roadmap

- **v0.3** — parse `poetry.lock` / `uv.lock` for real transitive dep counts
- **v0.3** — weight CVSS ≥ 9.0 CVEs more heavily in the score
- **v0.4** — `scori-action` for GitHub Actions, pre-commit hook

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
