# Changelog

All notable changes to this project are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
semantic versioning [SemVer](https://semver.org/).

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
