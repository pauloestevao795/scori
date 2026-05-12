# Changelog

All notable changes to this project are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
semantic versioning [SemVer](https://semver.org/).

## [Unreleased]

### Added

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
