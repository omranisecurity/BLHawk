# BugRap program intelligence

BLHawk can consume [BugRap](https://www.bugrap.io) program metadata to build an
authorized scope. It is **import-first and ToS-respecting**: BLHawk does not
mass-scrape the BugRap directory.

## Safe workflow

```
import/fetch program metadata  (user-authorized)
        ▼
cache with timestamps + detect scope changes
        ▼
convert program -> Scope
        ▼
VERIFY against the official program rules
        ▼
scan only IN_SCOPE targets
```

## Import (recommended)

Export program metadata to JSON/YAML and import it:

```sh
blhawk --import-programs programs.json
blhawk --platform bugrap --list-programs
blhawk --program bugrap:example-web3 -l urls.txt
```

Example `programs.json`:

```json
{
  "programs": [
    {
      "name": "example-web3",
      "url": "https://bugrap.io/bounties/example-web3",
      "bounty_range": "up to 5000 USDC",
      "assets": [
        {"asset": "*.example.org", "type": "wildcard", "scope": "in"},
        {"asset": "https://github.com/example/contracts", "type": "repository"},
        {"asset": "admin.example.org", "type": "domain", "scope": "out"}
      ],
      "restrictions": ["no automated scanning of the admin panel"]
    }
  ]
}
```

## Optional single-program fetch

```sh
blhawk --fetch-program https://bugrap.io/bounties/example --program example
```

This fetches **one** page you explicitly request, honors `robots.txt`, and
extracts scope on a best-effort basis. Program pages are often JS-rendered, so
importing exported metadata is more reliable. Always verify fetched scope
against the official rules before scanning.

## Caching & change detection

Programs are cached under `$BLHAWK_HOME` (or `~/.cache/blhawk`) with a
`scope_last_checked` timestamp. Re-importing reports added/removed assets so you
can detect scope changes. No permanent program list is hardcoded.

## Prioritization

`--list-programs` ranks programs by research suitability: in-scope asset count,
wildcard presence, BLHawk provider support, published bounty, and freshness.
Manual-testing-only programs are down-ranked and flagged. Prioritization does
not optimize for bounty size alone.
