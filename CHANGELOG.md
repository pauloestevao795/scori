# Changelog

All notable changes to this project are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
semantic versioning [SemVer](https://semver.org/).

## [0.7.1] - 2026-05-13

### Fixed

- Path traversal: `source_file` values from dependency results are now validated
  against a hardcoded allowlist (`_SAFE_MANIFEST_NAMES`) before being used in
  `shutil.copy2` or path concatenation — eliminates Snyk MEDIUM findings
- SHA-256 docstring correction in `history.py` (was incorrectly labelled SHA-1)
- Recursive manifest discovery: `scan()` now traverses subdirectories, skipping
  `.venv/`, `site-packages/`, `build/` and other non-source dirs
- Badge workflow commits now attributed to `pauloestevao` instead of
  `github-actions[bot]`

### Added

- `SECURITY.md`: vulnerability reporting policy and data-flow disclosure
- `pip-audit` step in CI: blocks on any CVE in scori's own dependencies

## [0.7.0] - 2026-05-13

### Added

- `scori fix` command: opens a GitHub pull request with the recommended
  dependency updates from `scori order`. Requires `GITHUB_TOKEN`. Default is
  dry run (shows the proposed PR table without touching git); `--apply` creates
  the branch, commits the version bumps, pushes, and opens the PR via the
  GitHub REST API. `--max-friction <label>` limits the updates included.
- `scori friction --format cyclonedx`: emits a CycloneDX 1.5 JSON Software
  Bill of Materials. Each component carries standard fields (`name`, `version`,
  `purl`) plus scori-specific properties: `scori:friction-score`, `scori:label`,
  `scori:version-jump`, `scori:latest-version`, `scori:cwe-ids`, and
  `scori:breaking-signals`. Enables downstream compliance tooling without
  requiring a separate SBOM tool.

## [0.6.0] - 2026-05-13

### Added

- `.pyi` stub diff as an opt-in breaking signal (`--stub-diff` flag on
  `scori friction` and `scori order`): downloads the current and latest wheels
  from PyPI, extracts public symbols from `.pyi` stubs (falling back to `.py`
  source), and reports removed public names as breaking signals. Off by default
  to avoid slowing down regular runs.
- Conflict detection in `scori order`: after ranking the update queue, scori
  now reads the lockfile to identify pairs of packages that share transitive
  dependencies. Packages in the same update batch with shared transitive deps
  are flagged with a "test together" warning so cascading changes aren't missed.
- Conda version resolution: `_current_version_from_spec` now tries
  `conda list --json` as a fallback when no local venv is found, so conda
  environments get accurate installed-version data without pinning.
- Pyenv version resolution: similarly, scori reads `.python-version` and checks
  the active pyenv Python's `site-packages` as an additional fallback.
- Dynamic friction badge for README: a new GitHub Actions workflow
  (`.github/workflows/badge.yml`) runs on every push to `main`, computes the
  average friction score across all project dependencies, writes a
  shields.io-compatible `badge.json`, and commits it back to the repo. The
  README badge auto-updates on the next page load.
- `CONTRIBUTING.md`: local setup, code style, how to add a new breaking-signal
  detector, and priority areas for external contribution.

## [0.5.0] - 2026-05-13

### Added

- Per-project `.scori.toml` configuration with three built-in risk profiles:
  `conservative` (threshold 50), `balanced` (threshold 75, default), and
  `aggressive` (threshold 90). An explicit `threshold` key in `[scori]`
  overrides the profile default. Packages listed under `[ignore] packages`
  are skipped entirely.
- Score history: every `scori friction` run appends a JSONL snapshot to
  `~/.local/share/scori/history/<project-sha1>.jsonl`. Use
  `scori history --path .` to view the last 10 snapshots with trend
  indicators (↑ rising, ↓ falling, — stable, ↕ fluctuating) per package.
- `scori order` command: ranks dependencies by recommended update order,
  balancing friction score with OSV vulnerability data to surface the highest
  value / lowest risk updates first.
- LLM changelog summary (`--summarise` flag on `scori friction`): calls Ollama
  (localhost:11434) first, then falls back to Claude (ANTHROPIC_API_KEY) and
  OpenAI (OPENAI_API_KEY). Returns a concise plain-English summary of what
  changes in a given update. Off by default — never required to use scori.
- Vuln column replaces the CVEs column in all output formats, now including
  CWE weakness IDs (e.g. `CWE-79`) collected from the OSV response and mapped
  to OWASP Top 10 2021 categories (e.g. `A03 Injection`).

## [0.4.0] - 2026-05-12

### Added

- `scori friction --format markdown`: outputs a GitHub-flavoured markdown table
  with emoji traffic-light indicators, a warning block for dependencies that
  exceeded the threshold, and an alternatives section — designed for automated
  PR comments.
- GitHub Actions composite action (`action.yml`): single-step integration that
  installs scori, runs the friction check, gates on a configurable threshold,
  and optionally posts the markdown table as a pull request comment
  (uses `--edit-last` to update rather than duplicate the comment on re-runs).
  Inputs: `path`, `threshold` (default 75), `github-token`, `comment-pr`,
  `format`. Output: `result` (JSON array of `FrictionResult` objects).
- Pre-commit hook (`.pre-commit-hooks.yaml`): add scori to
  `.pre-commit-config.yaml` with `repo: https://github.com/pauloestevao795/scori`.
  The hook runs `scori friction --ci` and blocks commits when any dependency
  exceeds the threshold. Only fires when manifest files change
  (`requirements*.txt`, `pyproject.toml`, `setup.cfg`).

## [0.3.0] - 2026-05-12

### Added

- Real transitive dependency counts via `uv.lock` / `poetry.lock` parsing:
  scori now reads the lockfile at the project root and counts how many other
  packages depend on the package being evaluated (reverse-dep count). This
  number feeds directly into the friction score (`+3 per dep, max 15`).
  Falls back to 0 when no lockfile is present. Supports both `uv.lock`
  (TOML-based) and `poetry.lock` formats.
- CVSS-weighted CVE scoring: CRITICAL-severity vulnerabilities (as reported
  by the GitHub Advisory Database via OSV `database_specific.severity`) now
  count double in the friction score calculation. A package with one CRITICAL
  CVE fixed by updating scores higher than a package with one LOW CVE fixed,
  pushing more urgent updates to the top of the queue.
- CHANGELOG.md scanning as an additional breaking signal source: scori now
  fetches `CHANGELOG.md` (and common variants) from the package's GitHub
  repository and scans the relevant version sections for breaking-change
  keywords alongside existing GitHub release notes scanning. Also detects
  `BREAKING CHANGE:` Conventional Commit footers in both release notes and
  CHANGELOG content.

## [0.2.0] - 2026-05-12

### Added

- Dynamic alternative library discovery for packages with unresolved CVEs:
  scori extracts keywords from the vulnerable package's PyPI metadata, queries
  the PyPI XMLRPC search API for similar packages, and cross-checks each
  candidate against the OSV database — returning up to 3 alternatives with
  0 known vulnerabilities. No hardcoded list; results are cached in-memory per
  run. Suggestions appear below the friction table in the CLI and in a
  dedicated section in the HTML report.
- `scori report` command: generates a polished standalone report
  - `--format html` (default): dark-theme HTML with traffic-light indicators,
    summary cards by label, and per-dependency recommendations; sorted by
    friction score descending
  - `--format json`: structured JSON suitable for CI/CD consumption
  - `--output FILE`: write to a custom path instead of `scori-report.html`
  - `--ci` / `--threshold`: exit 1 if any dependency exceeds the threshold
- `scori update` command with three modes:
  - `--dry-run`: shows a table of pending version bumps without touching files
  - `--apply`: writes updated versions to manifest files and creates a backup
    in `.scori-backup/`
  - `--rollback`: restores manifest files from the last backup
  - `--max-friction <label>`: limits updates to deps at or below the given
    friction label (`low`, `medium`, `high`, `critical`)
- `scori monitor` command: shows only dependencies with available updates,
  sorted by friction score (highest first); marks with ★ packages where
  updating fixes known CVEs
- `--watch` flag on `scori monitor` for continuous polling (default interval:
  300 s, configurable via `--interval`)
- CVEs fixed by the latest release now contribute up to +15 pts to the
  friction score (`+3` per fixed CVE, capped at 15); CVEs that persist in
  the latest version do not affect the score
- `--ci` flag on `scori friction`: exits with code 1 if any dependency score
  exceeds a configurable threshold (default: 75, override with `--threshold`)
- `CVEs` column in `scori friction` table showing known vulnerabilities per
  version via the OSV API
- Installed version resolution for unpinned dependencies by inspecting the
  project's local venv (`.venv/`, `venv/`, `env/`)

## [0.1.0] - 2026-05-12

### Added

- `scori scan`: reads requirements.txt, pyproject.toml, setup.cfg
- `scori friction`: computes friction score 0–100 per dependency
- Local cache in ~/.cache/scori/ with 1-hour TTL
- Output as table (CLI), JSON, and basic HTML
