# BLHawk

**Dead links aren't always dead.**

BLHawk is a dangling-reference / broken-link takeover research tool for
**authorized** security research. It identifies deleted resources and broken
links across many platforms and — crucially — tells you *how confident* it is
that a finding is actually security-relevant, instead of shouting "vulnerable"
at every HTTP 404.

> BLHawk is for authorized testing only. Only test assets that are explicitly
> in scope under the applicable bug bounty / vulnerability disclosure program.
> Never bypass authentication, rate limits, anti-abuse controls, CAPTCHAs, or
> program rules. See [Responsible use](#responsible-use).

## Why BLHawk is different

- **Confidence-based verdicts.** A 404 is not a vulnerability. BLHawk grades
  each target on a spectrum from `NOT_VULNERABLE` to
  `CONFIRMED_BY_SAFE_VERIFICATION`, and never claims a takeover it cannot
  substantiate.
- **Reclaimability awareness.** A missing PyPI project or Google Play app is a
  *dead resource* (the identifier cannot be re-registered), while a missing
  GitHub org may be *reclaimable*. BLHawk encodes this per provider.
- **Scope enforcement first.** With a scope loaded, only `IN_SCOPE` targets are
  scanned. Wildcards are matched safely (`*.example.com` never matches
  `example.com.evil.com`).
- **SSRF-safe by design.** Every request (including each redirect hop) is
  checked against a private/loopback/link-local/cloud-metadata blocklist. The
  scanner cannot be turned into an SSRF primitive.
- **Extensible providers.** Adding a platform means adding one small class — no
  giant `if/elif` chain.

## Installation

```sh
git clone https://github.com/omranisecurity/BLHawk.git
cd BLHawk
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"     # or: pip install -r requirements.txt
```

Requires Python 3.9+.

## Usage

```sh
# Single target
blhawk -u https://github.com/some-deleted-org

# A list of URLs, or stdin
blhawk -l urls.txt
cat urls.txt | blhawk --stdin

# Enforce a scope (only IN_SCOPE targets are scanned)
blhawk --scope scope.yaml -l urls.txt

# Use an imported BugRap program's scope
blhawk --import-programs programs.json
blhawk --platform bugrap --list-programs
blhawk --program bugrap:example-web3 -l urls.txt

# Output formats
blhawk -u https://example.com/x --format json
blhawk -u https://example.com/x --output results.json --csv results.csv

# See what would be tested without making security-testing requests
blhawk -l urls.txt --dry-run

# Utilities
blhawk --list-providers
blhawk --validate-scope scope.yaml
```

Key flags: `-u/--url`, `-l/--list`, `--stdin`, `--scope`, `--program`,
`--platform`, `--provider`, `--threads`, `--rate-limit`, `--timeout`,
`--format`, `--output/--jsonl/--csv/--markdown`, `--silent`, `--verbose`,
`--debug`, `--dry-run`, `--extract-links`, `--list-providers`,
`--list-programs`, `--validate-scope`, `--allow-private`.

`--allow-private` disables the SSRF guard for controlled testing of internal
hosts — only use it when you are explicitly authorized to.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `NOT_VULNERABLE` | Resource is present/live. |
| `UNKNOWN` | Not enough signal (blocked, transient error, soft-404, ambiguous). |
| `DEAD_RESOURCE` | Gone, but the identifier is not reclaimable (no takeover). |
| `POTENTIALLY_RECLAIMABLE` | Gone and the identifier may be re-registerable. |
| `RECLAIMABILITY_UNCONFIRMED` | Likely reclaimable; needs safe verification. |
| `LIKELY_TAKEOVER` / `CONFIRMED_BY_SAFE_VERIFICATION` | Reserved for verified evidence; never emitted by passive scanning. |

## Documentation

- [Architecture](docs/architecture.md)
- [Providers](docs/providers.md) (and how to add one)
- [Scope system](docs/scope.md)
- [BugRap integration](docs/bugrap.md)
- [Testing](docs/testing.md)
- [Development](docs/development.md)

## Testing

```sh
pytest                      # unit + integration (no network)
pytest -m live              # opt-in live tests (excluded from CI)
pytest --cov=blhawk         # coverage
python -m blhawk.benchmark  # throughput/memory benchmark
```

## Responsible use

BLHawk only identifies and prioritizes candidates. It never creates accounts,
claims resources, modifies third-party content, or demonstrates impact. Always
verify scope against the official program rules before scanning, respect
published rate limits and safe-harbor terms, and do not test out-of-scope or
third-party assets. You are responsible for using this tool lawfully and with
authorization.

## License

MIT — see [LICENSE](LICENSE).
