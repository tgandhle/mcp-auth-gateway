# Changelog

All notable changes to this project are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/), and the project aims to
follow semantic versioning once a tagged release is cut.

## [Unreleased]

### Added
- Continuous integration (`.github/workflows/ci.yml`): ruff lint, mypy
  type-check, bandit SAST, pytest, and pip-audit dependency scan, all installed
  from a pinned `uv.lock` for reproducible builds.
- `uv.lock` with hash-pinned dependencies.
- Property-based fuzzing of the JSON-RPC parser (`tests/test_parser_fuzz.py`),
  asserting the fail-closed contract over ~6k generated inputs.
- `CONTRIBUTING.md` documenting the local quality gate.
- Ruff, mypy, and bandit configuration in `pyproject.toml`.

### Changed
- `build()` in `__main__.py` now has a precise return type
  (`tuple[FastAPI, Settings]`), removing an incorrect `type: ignore` and making
  the source mypy-clean.
- Package author metadata corrected to `T. Gandhle`.
- Minor lint cleanups in the test suite (unused imports, import grouping).
