# Architecture

BLHawk is organized as a small set of composable subsystems.

```
blhawk/
├── cli/            # argument parsing + command dispatch
├── core/           # models, config, safe HTTP client, SSRF guard,
│                   # rate limiter, soft-404 detector, scan engine, logging
├── providers/      # one plugin per platform + registry
├── detection/      # provider signals -> verdict + confidence
├── scope/          # parse/normalize/match/classify authorized scope
├── discovery/      # target inputs + safe link extraction
├── bugrap/         # program intelligence (import/cache/prioritize)
├── output/         # terminal/json/jsonl/csv/markdown formatters
└── benchmark.py    # throughput/memory harness
```

## Data flow

```
inputs (-u/-l/stdin/scope/program)
        │  normalize + de-duplicate (core.engine.prepare_targets)
        ▼
scope classification (scope.matcher.classify_target)   ── only IN_SCOPE proceed
        ▼
provider selection (providers.registry.find_provider)
        ▼
provider.evaluate  ──▶ safe HTTP request (core.http_client + SSRF guard + rate limit)
        │                    │
        │                    └─ optional soft-404 control request
        ▼
detection.engine.classify  ──▶ Verdict + Severity + Confidence + Evidence
        ▼
Finding  ──▶ output formatters / research report
```

## Key design decisions

- **Confidence over booleans.** `core.models.Verdict` is an ordered enum. The
  detection engine caps escalation by *reclaimability* so a plain 404 never
  exceeds `DEAD_RESOURCE`, and passive scanning never emits a "confirmed"
  takeover.
- **Safety in the transport.** `core.http_client.SafeHTTPClient` follows
  redirects manually and re-runs the `core.ssrf.SSRFGuard` on every hop, caps
  response size, bounds redirects, and retries only transient failures.
- **Determinism.** The engine preserves input order, dedups on normalized URLs,
  and uses a virtual-clock-testable token-bucket rate limiter.
- **Extensibility.** Providers self-register; `find_provider` matches by host.
  Adding a platform is a single file (see [providers.md](providers.md)).

## Concurrency & cancellation

`core.engine.Scanner` uses a bounded `ThreadPoolExecutor`. A shared
`RateLimiter` enforces global and per-host limits across workers. `KeyboardInterrupt`
sets a cancel flag, stops submitting work, and returns partial results.
