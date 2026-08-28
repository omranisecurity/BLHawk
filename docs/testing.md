# Testing

BLHawk is tested primarily with fast, hermetic unit tests plus real-socket
integration tests. No test hits third-party services unless explicitly opted in.

## Running

```sh
pytest                       # unit + integration (mocked HTTP / local server)
pytest --cov=blhawk          # coverage
pytest -m live               # opt-in live tests (NOT run in CI)
```

`pyproject.toml` sets `addopts = -m 'not live'`, so live tests are excluded by
default and never run in CI.

## Test layout

- `test_ssrf.py`, `test_security.py` — SSRF blocklist, redirect re-validation,
  IPv4-mapped IPv6, response caps, log-injection, unsafe-deserialization,
  malicious input files.
- `test_http_client.py` — redirects, size caps, retries, scheme allowlist
  (mocked with `responses`).
- `test_rate_limiter.py` — token bucket with a virtual clock.
- `test_providers.py`, `test_providers_expansion.py` — per-provider
  present/missing/edge cases and reclaimability.
- `test_detection.py` — verdict mapping, soft-404, false-positive guards.
- `test_scope.py` — normalization, wildcard/CIDR matrix, precedence, parsers.
- `test_engine.py` — dedup, scope enforcement, dry-run, soft-404, ordering,
  cancellation.
- `test_cli.py`, `test_cli_bugrap.py`, `test_output.py` — CLI and formatters.
- `test_bugrap*.py` — program parsing, store/change-detection, prioritization,
  robots-respecting fetch.
- `test_integration.py` — real local HTTP server (controlled-testing mode) and
  the opt-in live test.

## Writing tests

Use the `client`/`public_guard` fixtures in `conftest.py` and the `responses`
library to mock HTTP. For real-socket tests, use a local `ThreadingHTTPServer`
with `allow_private=True` (the only way BLHawk reaches loopback).
