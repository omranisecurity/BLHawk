# Scope system

The scope subsystem (`blhawk/scope/`) turns authorization data into an
enforced, testable model. With a scope loaded, only `IN_SCOPE` targets are
scanned.

## Formats

- **txt** — one asset per line; `#` comments; `!` prefix marks an exclusion.
- **json** — `{"program": "...", "assets": [...], "out_of_scope": [...]}`.
- **yaml** — same shape, parsed with `yaml.safe_load` only.
- **csv** — columns `asset,type,scope[,program,...]`.

Validate with `blhawk --validate-scope scope.yaml`.

## Asset types

`domain`, `wildcard`, `url`, `api`, `ip`, `cidr`, `repository`, `package`,
`mobile_app`, `other`. Types are inferred when omitted.

## Classification

`classify_target(url, scope)` returns one of `IN_SCOPE`, `OUT_OF_SCOPE`,
`UNKNOWN`, `REQUIRES_MANUAL_REVIEW`.

- **Exclusions win.** Any matching `out` rule yields `OUT_OF_SCOPE`.
- **No match → `UNKNOWN`** (never scanned by default).
- Mobile apps / restricted assets → `REQUIRES_MANUAL_REVIEW`.

## Matching rules (security-critical)

- **Exact domain** matches only that host (`example.com`, not
  `api.example.com`).
- **Wildcard** `*.example.com` matches the apex and any subdomain, and
  rejects look-alikes: `example.com.evil.com`, `evil-example.com`,
  `example.org` are **not** in scope.
- **URL/API/repository** match host exactly plus a path prefix.
- **IP/CIDR** match by address membership (IPv4 and IPv6).
- Hosts are normalized: lowercased, trailing dot stripped, IDN/Unicode
  converted to punycode, IPv6 brackets removed.

See `tests/test_scope.py` for the full matrix.
