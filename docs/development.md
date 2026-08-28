# Development

## Setup

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Quality gates

```sh
ruff check blhawk tests        # lint (imports, bugbear, pyupgrade)
ruff format --check blhawk tests
mypy blhawk                    # type check
pytest --cov=blhawk            # tests + coverage
pip-audit                      # dependency vulnerability audit
python -m build                # build sdist/wheel
```

CI (`.github/workflows/python-package.yml`) runs all of these on Python
3.9–3.12. Live tests are never run in CI.

## Conventions

- `from __future__ import annotations` in every module; builtin generics and
  `X | Y` unions are fine.
- Keep the SSRF guard and scope enforcement intact — they are safety-critical.
- Every new provider and every feature ships with tests.
- Do not add dependencies casually; runtime deps are pinned in `pyproject.toml`.

## Releasing

Bump `blhawk/version.py` and `pyproject.toml`, ensure the gates pass, then build
and tag.

## Project layout

See [architecture.md](architecture.md).
