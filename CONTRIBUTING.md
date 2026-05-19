# Contributing to scori

Thank you for your interest in contributing. This document covers everything you need to set up a local development environment, run the tests, and submit a pull request.

---

## Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) — used for all package management and task running

---

## Local setup

```bash
git clone https://github.com/pauloestevao795/scori
cd scori
uv sync --group dev
uv run pre-commit install
```

`uv sync` creates the virtual environment and installs all dependencies (including dev dependencies). `pre-commit install` sets up the git hook that runs ruff, mypy, and the test suite on every commit.

---

## Running checks

```bash
# Lint
uv run ruff check .

# Format (check only)
uv run ruff format --check .

# Type check
uv run mypy src/scori/

# Tests (unit, no network)
uv run pytest

# Integration tests (requires network)
uv run pytest -m integration

# All at once
uv run ruff check . && uv run ruff format --check . && uv run mypy src/scori/ && uv run pytest
```

All four checks must pass before a pull request can be merged.

---

## Project structure

```
src/scori/
  __init__.py       stable public API (compute, scan, Dependency, FrictionResult, …)
  __main__.py       CLI (argparse, rich)
  _types.py         TypedDicts: Dependency, FrictionResult, FrictionLabel, VersionJump
  friction.py       core scoring logic, PyPI/GitHub/OSV fetching
  scanner.py        manifest parser (requirements.txt, pyproject.toml, setup.cfg,
                    Pipfile, environment.yml/conda.yml)
  lockfile.py       uv.lock / poetry.lock parser + conflict detection
  config.py         per-project .scori.toml profiles
  fix.py            GitHub PR automation for scori fix
  sbom.py           CycloneDX 1.5 SBOM generation
  history.py        JSONL score history + trend computation
  summarise.py      LLM changelog summary (Ollama → Claude → OpenAI)
  stubdiff.py       .pyi stub diff for API removal detection

tests/
  test_friction.py
  test_scanner.py
  test_lockfile.py
  test_config.py
  test_history.py
  test_fix.py
  test_sbom.py
  test_stubdiff.py
  test_integration.py   # requires network; run with: pytest -m integration
```

---

## Making changes

1. **Create a branch** from `main`.
2. **Write tests first** (or alongside your change). Every new function should have at least one test.
3. **Run the full check suite** before pushing.
4. **Update documentation**: if your change affects behaviour visible to users, update `README.md`, `CHANGELOG.md` (under `[Unreleased]`), and `ROADMAP.md` as appropriate.
5. **Open a pull request** against `main`. The PR description should explain *what* changed and *why*.

---

## Code style

- **Formatter**: ruff (line length 88, configured in `pyproject.toml`)
- **Linter**: ruff with a strict rule set — see `[tool.ruff.lint]` in `pyproject.toml`
- **Types**: all public functions must have full type annotations; mypy runs in strict mode
- **Comments**: default to writing none. Add a comment only when the *why* is non-obvious. No docstrings that restate what the function name already says.
- **No new abstractions** beyond what the task requires. Three similar lines is better than a premature helper.

---

## Adding a new breaking-signal detector

`_scan_breaking` in [friction.py](src/scori/friction.py) is the central place for breaking signal detection. To add a new source:

1. Write a function that returns `list[str]` (each string is one signal).
2. Call it from `compute()` and append its results to `signals`.
3. If it requires network access, make it opt-in (add a flag, or run only when a condition is met — see `stub_diff` for an example).
4. Add tests that mock the network layer using the `responses` library.

---

## Reporting bugs

Open a GitHub issue and include:

- scori version (`scori --version`)
- Python version (`python --version`)
- The manifest file(s) being scanned (or a minimal reproduction)
- The full error output

---

## Priority areas for contribution

- Multi-ecosystem adapters: Node.js (`package.json` + npm API), Go (`go.mod`), Rust (`Cargo.toml`)
- CLI internationalisation (i18n)
- Conda/pyenv version resolution improvements
- `Pipfile.lock` parser for accurate transitive counts (analogous to `lockfile.py`)

Issues labelled **`good first issue`** are the recommended starting point.

---

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
