"""Argument parsing and command dispatch for BLHawk."""
from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from ..core.config import ScanConfig
from ..core.engine import Scanner
from ..core.errors import BLHawkError
from ..core.logging import configure_logging, get_logger
from ..core.models import Finding
from ..discovery.inputs import read_stdin, read_target_file, targets_from_scope
from ..discovery.urls import extract_links
from ..output.formatters import FORMATS, format_findings, write_findings
from ..providers.registry import get_providers
from ..scope.model import Scope
from ..scope.parsers import load_scope_file
from ..version import __version__

_log = get_logger("cli")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="blhawk",
        description="BLHawk - dangling-reference / broken-link takeover research tool "
        "for authorized security research.",
        epilog=f"version {__version__}",
    )
    p.add_argument("targets", nargs="*", help="target URLs")
    p.add_argument("-u", "--url", action="append", default=[], help="target URL (repeatable)")
    p.add_argument("-l", "--list", dest="list_file", help="file with one target per line")
    p.add_argument("--stdin", action="store_true", help="read targets from stdin")
    p.add_argument("--scope", help="scope file (txt/json/yaml/csv)")
    p.add_argument("--program", help="program identifier, e.g. bugrap:<name>")
    p.add_argument("--platform", help="program platform (e.g. bugrap)")
    p.add_argument("--provider", help="only scan targets handled by this provider")
    p.add_argument("--threads", type=int, default=5, help="concurrent workers (default 5)")
    p.add_argument("--rate-limit", type=float, default=2.0,
                   help="per-host requests/sec (default 2)")
    p.add_argument("--global-rate", type=float, default=5.0,
                   help="global requests/sec (default 5)")
    p.add_argument("--timeout", type=float, default=15.0, help="request timeout seconds")
    p.add_argument("--format", choices=FORMATS, default="terminal", help="stdout format")
    p.add_argument("--output", help="write JSON results to this file")
    p.add_argument("--jsonl", help="write JSONL results to this file")
    p.add_argument("--csv", help="write CSV results to this file")
    p.add_argument("--markdown", help="write Markdown report to this file")
    p.add_argument("--silent", action="store_true", help="machine-readable output only")
    p.add_argument("--verbose", action="store_true", help="verbose output")
    p.add_argument("--debug", action="store_true", help="debug logging")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--no-soft404", action="store_true", help="disable soft-404 probing")
    p.add_argument("--dry-run", action="store_true",
                   help="show what would be tested without security-testing requests")
    p.add_argument("--extract-links", action="store_true",
                   help="fetch each -u page and scan the links it contains")
    p.add_argument("--allow-private", action="store_true",
                   help="DANGER: disable SSRF guard (controlled testing only)")
    p.add_argument("--list-providers", action="store_true", help="list providers and exit")
    p.add_argument("--list-programs", action="store_true", help="list programs and exit")
    p.add_argument("--import-programs", help="import program metadata (JSON/YAML) into the store")
    p.add_argument("--fetch-program",
                   help="fetch a single program page (robots-respecting) into the store")
    p.add_argument("--store-dir", help="directory for the BugRap program store cache")
    p.add_argument("--validate-scope", help="parse and summarize a scope file, then exit")
    p.add_argument("--version", action="version", version=f"BLHawk {__version__}")
    return p


def _configure_logging(args: argparse.Namespace) -> None:
    if args.debug:
        level = logging.DEBUG
    elif args.verbose:
        level = logging.INFO
    elif args.silent:
        level = logging.ERROR
    else:
        level = logging.WARNING
    configure_logging(level)


def _print_providers() -> int:
    print("Available providers:")
    for provider in get_providers():
        hosts = ", ".join(provider.hosts) or "(suffix-matched)"
        print(f"  {provider.name:<14} {provider.resource_type:<22} [{hosts}]")
    return 0


def _validate_scope(path: str) -> int:
    try:
        scope = load_scope_file(path)
    except BLHawkError as exc:
        print(f"scope error: {exc}", file=sys.stderr)
        return 1
    print(f"Scope OK: {len(scope.includes)} in-scope, {len(scope.excludes)} excluded")
    for entry in scope.entries:
        marker = "-" if entry.is_exclude else "+"
        print(f"  {marker} [{entry.type.value}] {entry.asset}")
    return 0


def _load_scope(args: argparse.Namespace) -> Scope | None:
    if args.scope:
        return load_scope_file(args.scope)
    if args.program:
        from ..bugrap.integration import resolve_program_scope

        return resolve_program_scope(args.platform, args.program, args.store_dir)
    return None


def _list_programs(args: argparse.Namespace) -> int:
    from ..bugrap.integration import list_programs_cli

    return list_programs_cli(args.platform, args.store_dir)


def _import_programs(args: argparse.Namespace) -> int:
    from ..bugrap.integration import import_programs_file

    try:
        return import_programs_file(args.import_programs, args.store_dir)
    except BLHawkError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _fetch_program(args: argparse.Namespace) -> int:
    from ..bugrap.fetch import fetch_program
    from ..bugrap.integration import get_store

    config = ScanConfig(timeout=args.timeout, allow_private=args.allow_private)
    scanner = Scanner(config=config)
    try:
        program = fetch_program(scanner.http, args.fetch_program, name=args.program)
        change = get_store(args.store_dir).upsert(program)
    except BLHawkError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        f"Fetched '{program.name}' with {len(program.in_scope_assets)} in-scope asset(s); "
        f"{'new' if change.is_new else 'updated'}. VERIFY against official rules before scanning."
    )
    return 0


def _gather_targets(args: argparse.Namespace, scope: Scope | None, scanner: Scanner) -> list[str]:
    targets: list[str] = list(args.targets) + list(args.url)
    if args.list_file:
        targets.extend(read_target_file(args.list_file))
    if args.stdin:
        targets.extend(read_stdin())
    if args.extract_links:
        targets = _expand_links(args, scanner, targets)
    if not targets and scope is not None:
        targets = targets_from_scope(scope)
    return targets


def _expand_links(args: argparse.Namespace, scanner: Scanner, pages: list[str]) -> list[str]:
    discovered: list[str] = []
    for page in pages:
        url = page if "://" in page else "https://" + page
        try:
            resp = scanner.http.get(url)
        except BLHawkError as exc:
            _log.warning("could not fetch %s for link extraction: %s", url, exc)
            continue
        discovered.extend(extract_links(resp.text))
    return discovered


def _emit(findings: list[Finding], args: argparse.Namespace) -> None:
    text = format_findings(
        findings,
        fmt=args.format,
        use_color=not args.no_color and sys.stdout.isatty(),
        verbose=args.verbose,
        silent=args.silent,
    )
    sys.stdout.write(text)
    if args.output:
        write_findings(findings, args.output, "json")
    if args.jsonl:
        write_findings(findings, args.jsonl, "jsonl")
    if args.csv:
        write_findings(findings, args.csv, "csv")
    if args.markdown:
        write_findings(findings, args.markdown, "markdown")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args)

    if args.list_providers:
        return _print_providers()
    if args.validate_scope:
        return _validate_scope(args.validate_scope)
    if args.import_programs:
        return _import_programs(args)
    if args.fetch_program:
        return _fetch_program(args)
    if args.list_programs:
        return _list_programs(args)

    try:
        scope = _load_scope(args)
    except BLHawkError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    config = ScanConfig(
        threads=args.threads,
        per_host_rate=args.rate_limit,
        global_rate=args.global_rate,
        timeout=args.timeout,
        dry_run=args.dry_run,
        allow_private=args.allow_private,
        enable_soft404=not args.no_soft404,
    )
    try:
        config.validate()
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    scanner = Scanner(config=config, scope=scope)
    targets = _gather_targets(args, scope, scanner)

    if args.provider:
        from ..providers.registry import get_provider

        wanted = get_provider(args.provider)
        if wanted is None:
            print(f"error: unknown provider '{args.provider}'", file=sys.stderr)
            return 2
        targets = [t for t in targets if wanted.matches(_host_of(t))]

    if not targets:
        print("error: no targets provided (use -u, -l, --stdin, --scope)", file=sys.stderr)
        return 2

    try:
        findings = scanner.scan(targets)
    except BLHawkError as exc:
        print(f"scan error: {exc}", file=sys.stderr)
        return 1

    _emit(findings, args)
    return 0


def _host_of(target: str) -> str:
    from urllib.parse import urlsplit

    url = target if "://" in target else "https://" + target
    return (urlsplit(url).hostname or "").lower()


if __name__ == "__main__":
    raise SystemExit(main())
