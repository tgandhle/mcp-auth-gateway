# Contributing

## Local development

This project uses [uv](https://docs.astral.sh/uv/) for dependency management.
The committed `uv.lock` pins every dependency (with hashes) so local and CI
environments match.

```bash
# Install everything, including dev tooling, from the lock file.
uv sync --frozen --extra dev
```

## Running the quality gate

CI runs exactly these steps. Run them locally before opening a PR; if they pass
here, they pass in CI.

```bash
uv run ruff check src tests     # lint
uv run mypy src                 # type-check (source only, day-one strictness)
uv run bandit -c pyproject.toml -r src   # SAST
uv run pytest -q                # tests, including JSON-RPC parser fuzzing
uvx pip-audit                   # dependency CVE scan
```

## Notes on the toolchain

- **mypy** is intentionally not in strict mode yet. It type-checks `src` only;
  test typing is not gated. Strictness will tighten incrementally.
- **bandit** scans `src` only. Tests legitimately use `assert` and fake tokens,
  which bandit would otherwise flag.
- **pytest** includes property-based fuzzing of the JSON-RPC parser
  (`tests/test_parser_fuzz.py`). The parser is the security boundary: the fuzz
  tests assert it never resolves a forwardable method except for a well-formed
  single request with a non-empty string `method`.

## Updating dependencies

If you change `pyproject.toml`, regenerate the lock:

```bash
uv lock
```

CI installs with `--frozen` and will fail if `uv.lock` is out of date, so commit
the regenerated lock alongside the `pyproject.toml` change.
