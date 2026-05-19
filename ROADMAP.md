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

- [x] Parse `uv.lock` to count packages that depend on the package being updated
- [x] Parse `poetry.lock` for the same
- [x] Use the resolved count in the score weight (currently always 0)

### CVEs in the score

- [x] Incorporate OSV CVE count directly into the weighted algorithm (up to +15 pts)
- [x] Weight CVSS ≥ 9.0 CVEs more heavily than lower-severity ones

### Improved breaking signal detection

- [x] Scan `CHANGELOG.md` from the GitHub repo in addition to release notes
- [x] Detect `BREAKING CHANGE:` in Conventional Commits commit history
- [x] Heuristic diff of `.pyi` type stub files between versions as an API-change signal (`--stub-diff`)

### Broader version resolution

- [x] Resolve unpinned versions via `conda list --json` when inside a conda environment
- [x] Support pyenv shims as a version source
- [ ] Optional: detect version from Docker image labels (requires Docker CLI, off by default)

---

## v0.4 — Integrations

Bring scori into the workflows and tools developers already use.

### GitHub Actions

- [x] Composite action (`action.yml`) — install scori + run friction check in one step
- [x] Automatic PR comment with the markdown friction table (`comment-pr: true`)
- [x] Dynamic badge for `README.md` showing the project's average friction score (`badge.json` via GitHub Actions)

### Pre-commit hook

- [x] Official hook for `.pre-commit-config.yaml` (`.pre-commit-hooks.yaml`)
- [x] Configurable threshold — block commit if any dep exceeds it

---

## v0.5 — Intelligence layer ✅

Higher-level features that turn scori from a scoring tool into a maintenance advisor.

### Score history

- [x] Track friction scores over time per project in local storage (JSONL at `~/.local/share/scori/history/`)
- [x] Trend indicators per package (↑ ↓ — ↕) via `scori history --path .`

### Risk profiles

- [x] Per-project `.scori.toml` configuration for custom thresholds and weights
- [x] Built-in profiles: `conservative` (50), `balanced` (75), `aggressive` (90)
- [x] `[ignore] packages` list to skip specific dependencies entirely

### Suggested update order

- [x] `scori order` command: ranks deps by update priority (friction + vuln data)
- [x] Detect conflicts between simultaneous updates: shared transitive deps flagged in `scori order`

### LLM-assisted changelog summary *(opt-in)*

- [x] Plain-language summary of what changes in a given update (`--summarise`)
- [x] Supports local inference via Ollama, Claude (ANTHROPIC_API_KEY), or OpenAI (OPENAI_API_KEY)
- [x] Off by default; enabled explicitly with `--summarise`

### Vuln column (CWE / OWASP)

- [x] Renamed CVEs column to Vuln across all output formats
- [x] Collect CWE IDs from OSV `database_specific.cwe_ids` field
- [x] Map CWE IDs to OWASP Top 10 2021 categories via `_CWE_TO_OWASP`

---

## v0.7 — `scori fix` and SBOM output ✅

Two additions with high real-world impact that require no new concepts — just
building on the data already computed.

### `scori fix` — automated update PR

- [x] `scori fix --path . [--apply] [--max-friction LABEL]`: open a GitHub PR
  with the recommended updates; dry run by default, `--apply` creates the PR
- [x] PR body includes the full friction table ordered by lowest risk first
- [x] `--max-friction <label>`: limit updates included in the PR

### SBOM output (CycloneDX)

- [x] `scori friction --format cyclonedx`: CycloneDX 1.5 JSON with purl,
  `scori:friction-score`, `scori:label`, `scori:cwe-ids`, `scori:breaking-signals`
- [x] Enables downstream compliance tooling (NTIA, EU CRA, US EO 14028)

---

## v1.0 — Stable release ✅

- [x] Stable public API guarantee: `FrictionResult`, `Dependency`, `compute()`
  will not change in backwards-incompatible ways in 1.x releases
- [x] `Pipfile` / `Pipfile.lock` manifest support
- [x] `conda.yml` / `environment.yml` environment file support
- [x] Integration test suite against well-known real-world projects (`-m integration`)
- [x] Performance: parallel HTTP fetching across dependencies via `ThreadPoolExecutor`

---

## Beyond Python — scori for other ecosystems

The friction score algorithm is language-agnostic. The language-specific parts
are thin adapters: a manifest parser, a registry client, and a lockfile parser.
OSV already covers npm, Rust, Go, Ruby, Maven, NuGet, and Dart — so the
vulnerability layer transfers immediately to most target ecosystems.

The implementation strategy is a **single Python project** with per-ecosystem
adapter modules, exposed via a `--lang` flag:

```shell
scori friction --lang npm
scori friction --lang go
scori friction --lang java
```

This keeps all scoring logic, CLI, cache, and output formats shared. Each
ecosystem contributes only three modules: a manifest parser, a registry client,
and a lockfile parser.

### Ecosystem support matrix

| Ecosystem | Manifest | Lockfile | Registry | OSV |
| --- | --- | --- | --- | --- |
| **Node.js** | `package.json` | `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` | npm registry API | ✓ |
| **Go** | `go.mod` | `go.sum` | proxy.golang.org | ✓ |
| **Java** | `pom.xml` / `build.gradle` | `gradle.lockfile` | Maven Central API | ✓ |
| **Rust** | `Cargo.toml` | `Cargo.lock` | crates.io API | ✓ / RustSec |
| **Ruby** | `Gemfile` | `Gemfile.lock` | rubygems.org API | ✓ |
| **C# / .NET** | `*.csproj` / `packages.config` | — | NuGet API | ✓ |
| **PHP** | `composer.json` | `composer.lock` | Packagist API | partial |
| **Dart / Flutter** | `pubspec.yaml` | `pubspec.lock` | pub.dev API | ✓ |
| **Swift** | `Package.swift` | `Package.resolved` | Swift Package Index API | limited |
| **Elixir** | `mix.exs` | `mix.lock` | Hex.pm API | — |
| **Lua** | `*.rockspec` | — | LuaRocks API | — |

---

## v1.1 — Node.js ecosystem ✅

The highest-value target: largest package registry in the world, frequent
security events, and full OSV coverage.

- [x] Parse `package.json` (dependencies + devDependencies)
- [x] Resolve installed versions from `package-lock.json` (v1/v2/v3),
  `yarn.lock` (classic + berry), and `pnpm-lock.yaml` (v6/v8/v9)
- [x] Fetch metadata from the npm registry API (version history, publish dates,
  deprecation flags); trimmed payload cached at `~/.cache/scori/npm_{pkg}.json`
- [x] Transitive dep count via `package-lock.json` reverse-dep graph
- [x] `--lang npm` flag wires all of the above into `scori friction` and
  `scori monitor`; `deprecated` maps to the `yanked` field in `FrictionResult`

---

## v1.2 — Go and Rust

Both have excellent OSV/RustSec coverage and deterministic lockfiles, making
the friction signal high-quality from day one.

### Go

- [ ] Parse `go.mod` for direct dependencies
- [ ] Resolve versions from `go.sum`
- [ ] Fetch metadata via proxy.golang.org and pkg.go.dev
- [ ] Transitive count from the module graph

### Rust

- [ ] Parse `Cargo.toml`
- [ ] Resolve versions from `Cargo.lock`
- [ ] Fetch metadata from crates.io API
- [ ] Pull advisory data from RustSec (`rustsec.org/advisories`) in addition to OSV

---

## v1.3 — Java and C# / .NET

Enterprise ecosystems with high update friction in practice — exactly the
problem scori was built to quantify.

### Java

- [ ] Parse `pom.xml` (Maven) and `build.gradle` / `build.gradle.kts` (Gradle)
- [ ] Resolve pinned versions from `gradle.lockfile` where present
- [ ] Fetch metadata from Maven Central Search API
- [ ] Map OSV advisories for Maven ecosystem

### C# / .NET

- [ ] Parse `*.csproj` and legacy `packages.config`
- [ ] Fetch metadata from the NuGet V3 API
- [ ] OSV NuGet ecosystem coverage

---

## v1.4 — Ruby, PHP, and Dart / Flutter

- [ ] **Ruby**: parse `Gemfile`, resolve from `Gemfile.lock`, rubygems.org API
- [ ] **PHP**: parse `composer.json`, resolve from `composer.lock`, Packagist API;
  note partial OSV coverage — supplement with the
  [PHP Security Advisories Database](https://github.com/FriendsOfPHP/security-advisories)
- [ ] **Dart / Flutter**: parse `pubspec.yaml`, resolve from `pubspec.lock`,
  pub.dev API, full OSV coverage

---

## v1.5 — Swift, Elixir, and Lua

Lower-priority ecosystems with limited or no OSV coverage; friction score is
still meaningful via version-jump and maintenance signals even without CVE data.

- [ ] **Swift**: parse `Package.swift`, resolve from `Package.resolved`,
  Swift Package Index API; CVE data limited to GitHub Advisory Database entries
- [ ] **Elixir**: parse `mix.exs`, resolve from `mix.lock`, Hex.pm API;
  no OSV coverage — score based on version-jump and maintenance signals only
- [ ] **Lua**: parse `*.rockspec`, LuaRocks API; no OSV coverage — score based
  on version-jump and maintenance signals only

---

## Non-goals

scori has a deliberate scope. The following are explicitly out of scope:

- **Not a CVE scanner.** scori shows CVE counts as context, but `pip-audit` and
  OSV-Scanner do this properly. Use them alongside scori, not instead.
- **Not a package manager.** scori reads and optionally edits manifests, but it
  does not resolve or install packages.
- **No account required.** scori will never require a login, subscription, or
  mandatory API key. Optional tokens (e.g. `GITHUB_TOKEN`) improve rate limits,
  but the tool is always fully functional without them.

---

## How to contribute

Contributions are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the
full guide.

**Priority areas for external contributions:**

- Integration tests against well-known real-world projects
- `Pipfile` / `Pipfile.lock` manifest parser
- `conda.yml` environment file parser
- Parallel HTTP fetching in `compute()` for faster multi-dependency runs

Issues labelled **`good first issue`** on GitHub are the recommended starting
point for new contributors.

---

## Versioning policy

scori follows [Semantic Versioning](https://semver.org).

- Patch releases (`0.x.y`) fix bugs without changing behaviour.
- Minor releases (`0.x`) add features in a backwards-compatible way.
- Breaking changes to the CLI interface will only occur in major releases.
- The public Python API (`FrictionResult`, `Dependency`, `compute()`) is
  considered stable from v1.0 onwards.
