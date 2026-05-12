# scori Roadmap

> *Know the cost before you update.*

scori is a free, auth-free CLI for Python that quantifies the real cost of updating a dependency as a single friction score (0–100). It complements tools like `pip-audit`, OSV-Scanner, and Dependabot — which tell you *what* to update — by answering the harder question: *should you update it now, and how much will it hurt?* The friction score is a concept not yet present in open-source dependency tooling, and scori aims to make it a first-class signal in every Python project's maintenance workflow.

---

## Current status — v0.1.0 ✅

- [x] `scori scan`: reads `requirements.txt`, `pyproject.toml` (PEP 517/518), `setup.cfg`
- [x] `scori friction`: computes friction score 0–100 per dependency
- [x] Weighted scoring algorithm: version jump, breaking signals, transitive deps, months outdated, yanked status
- [x] Labels: Low / Medium / High / Critical with color-coded table output
- [x] CVEs column via [OSV API](https://osv.dev) — shown as `3 → 0 ✓`, separate from the score
- [x] Output formats: table (rich), JSON, HTML
- [x] Local cache in `~/.cache/scori/` with 1-hour TTL (PyPI + GitHub data)
- [x] `GITHUB_TOKEN` support to raise API rate limit from 60/h to 5000/h
- [x] Installed version resolution for unpinned deps via local venv inspection

**Known limitations in v0.1.0:**

- Unpinned dependencies without a local venv fall back to `0.0.0` (no conda/pyenv/Docker support yet)
- Transitive dependency count is always 0 — requires a lockfile parser (planned for v0.3)
- CVE count is informational only — not yet factored into the friction score
- `scori monitor`, `scori update`, and `scori report` are stubbed in the CLI but not implemented

---

## v0.2 — Full CLI surface

Complete the commands already declared in the CLI but not yet implemented.

### `scori monitor` ✅

- [x] Poll PyPI for new releases on all project dependencies
- [x] Output a "updates available" table sorted by friction score (highest friction first)
- [x] `--watch` flag for continuous monitoring with a configurable interval
- [x] Highlight dependencies where a new release also fixes known CVEs (★ marker)

### `scori update` ✅

- [x] `--dry-run`: show a diff of what would change in the manifest without applying
- [x] `--apply`: apply updates and create an automatic backup of the original manifest
- [x] `--rollback`: restore the most recent backup
- [x] `--max-friction <label>`: only update deps at or below a given friction label (e.g. `medium`)

### `scori report` ✅

- [x] Standalone HTML report with a visual traffic-light indicator per dependency
- [x] Structured JSON export suitable for CI/CD pipeline consumption
- [x] `--ci` flag: exit with code 1 if any dependency exceeds a configurable score threshold

---

## v0.3 — Smarter scoring

Improve the accuracy and depth of the friction score algorithm.

### Real transitive dependency counts

- [ ] Parse `poetry.lock` to count packages that depend on the package being updated
- [ ] Parse `uv.lock` for the same
- [ ] Use the resolved count in the score weight (currently always 0)

### CVEs in the score

- [x] Incorporate OSV CVE count directly into the weighted algorithm (up to +15 pts)
- [ ] Weight CVSS ≥ 9.0 CVEs more heavily than lower-severity ones

### Improved breaking signal detection

- [ ] Scan `CHANGELOG.md` from the GitHub repo in addition to release notes
- [ ] Detect `BREAKING CHANGE:` in Conventional Commits commit history
- [ ] Heuristic diff of `.pyi` type stub files between versions as an API-change signal

### Broader version resolution

- [ ] Resolve unpinned versions via `conda list --json` when inside a conda environment
- [ ] Support pyenv shims as a version source
- [ ] Optional: detect version from Docker image labels (requires Docker CLI, off by default)

---

## v0.4 — Integrations

Bring scori into the workflows and tools developers already use.

### GitHub Actions

- [ ] Official `scori-action` published to the GitHub Marketplace
- [ ] Automatic PR comment with a friction table for any changed dependencies
- [ ] Dynamic badge for `README.md` showing the project's average friction score

### Pre-commit hook

- [ ] Official hook for `.pre-commit-config.yaml`
- [ ] Configurable threshold — block commit if any dep exceeds it

### VSCode Extension *(stretch goal)*

- [ ] Inline decoration showing the friction score per line in `requirements.txt` / `pyproject.toml`
- [ ] CodeLens action: "Run scori friction on this package"

---

## v0.5 — Intelligence layer

Higher-level features that turn scori from a scoring tool into a maintenance advisor.

### Score history

- [ ] Track friction scores over time per project in local storage
- [ ] Trend chart: surface dependencies that are becoming riskier over successive runs

### Risk profiles

- [ ] Per-project `.scori.toml` configuration for custom thresholds and weights
- [ ] Built-in profiles: `conservative`, `balanced`, `aggressive`

### Suggested update order

- [ ] Rank dependencies by update order to minimise total migration risk
- [ ] Detect conflicts between simultaneous updates (e.g. shared transitive dep with incompatible constraints)

### LLM-assisted changelog summary *(opt-in)*

- [ ] Plain-language summary of what changes in a given update
- [ ] Supports local inference via Ollama or `OPENAI_API_KEY` — never required to use scori
- [ ] Off by default; enabled explicitly with `--summarise`

---

## Non-goals

scori has a deliberate scope. The following are explicitly out of scope:

- **Not a CVE scanner.** scori shows CVE counts as context, but `pip-audit` and OSV-Scanner do this properly. Use them alongside scori, not instead.
- **Not a package manager.** scori reads and optionally edits manifests, but it does not resolve or install packages.
- **Python only.** Supporting npm, cargo, or other ecosystems is out of scope. scori's scoring model is designed around the PyPI and GitHub release data available for Python packages.
- **No account required.** scori will never require a login, subscription, or mandatory API key. Optional tokens (e.g. `GITHUB_TOKEN`) may improve rate limits, but the tool is always fully functional without them.

---

## How to contribute

Contributions are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) (coming soon) for the full guide.

**Priority areas for external contributions:**

- Manifest parsers for additional formats (`conda.yml`, `Pipfile`, `Pipfile.lock`)
- Integration tests against well-known real-world projects
- CLI message internationalisation (i18n)

Issues labelled **`good first issue`** on GitHub are the recommended starting point for new contributors.

---

## Versioning policy

scori follows [Semantic Versioning](https://semver.org).

- Patch releases (`0.x.y`) fix bugs without changing behaviour.
- Minor releases (`0.x`) add features in a backwards-compatible way.
- Breaking changes to the CLI interface will only occur in major releases.
- The public API (`FrictionResult`, `Dependency`, `compute()`) is considered stable from v1.0 onwards. Until then, minor releases may include breaking changes to the Python API — the CLI surface is the stable interface.
