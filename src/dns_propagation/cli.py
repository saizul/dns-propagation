"""Command line interface."""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections.abc import Callable, Sequence
from typing import TextIO

from ._version import __version__
from .check import CheckError, Expectation, Report, expectation_from_authoritative, run_check, watch
from .emailauth import EMAIL_CHECKS, check_domain
from .output import (
    Style,
    render_email,
    render_report,
    render_resolvers,
    render_round,
    reports_document,
    to_json,
)
from .query import DnsQuerier, Querier, QueryResult
from .records import MATCH_MODES, RECORD_TYPES, check_type
from .resolvers import BUILTIN, REGIONS, Resolver, ResolverError, Target, load_file, parse_custom, select, targets_for

EXIT_OK = 0
EXIT_NOT_PROPAGATED = 1
EXIT_USAGE = 2
EXIT_DNS_FAILURE = 3

COMMANDS = ("check", "watch", "email", "resolvers")


class UsageError(Exception):
    pass


def _csv(values: Sequence[str] | None) -> list[str]:
    out: list[str] = []
    for value in values or ():
        out.extend(v.strip() for v in value.split(",") if v.strip())
    return out


def _add_selection(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("resolvers")
    group.add_argument(
        "-r",
        "--resolvers",
        action="append",
        metavar="IDS",
        help="comma separated resolver ids or providers (see 'resolvers'); default: all built-in",
    )
    group.add_argument(
        "--region",
        action="append",
        metavar="REGION",
        help=f"only resolvers in a region ({', '.join(REGIONS)}) or country",
    )
    group.add_argument(
        "--resolver",
        dest="custom",
        action="append",
        metavar="[NAME=]ADDRESS",
        help="add a custom resolver: an IP address or an https:// DoH URL (repeatable)",
    )
    group.add_argument(
        "--resolvers-file", metavar="FILE", help="read resolvers from a file instead of the built-in list"
    )
    group.add_argument(
        "--no-filtering", action="store_true", help="skip resolvers that block domains (malware/ad filtering)"
    )
    group.add_argument(
        "--transport",
        choices=("udp", "tcp", "doh", "all"),
        default="udp",
        help="plain DNS (udp, TCP fallback), TCP only, DNS over HTTPS (doh) or udp and doh (all); default: udp",
    )
    group.add_argument(
        "--doh", dest="transport", action="store_const", const="doh", help="shortcut for --transport doh"
    )
    group.add_argument(
        "--tcp", dest="transport", action="store_const", const="tcp", help="shortcut for --transport tcp"
    )


def _add_output(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("output")
    group.add_argument("--json", action="store_true", help="print JSON")
    group.add_argument("--no-color", action="store_true", help="disable colours (also NO_COLOR)")
    group.add_argument("--wide", action="store_true", help="do not truncate long answers")


def _add_check_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("name", help="domain name to look up")
    parser.add_argument("types", nargs="*", metavar="TYPE", help=f"record types ({', '.join(RECORD_TYPES)}); default A")
    parser.add_argument(
        "-t", "--type", dest="type_opts", action="append", metavar="TYPE", help="record type (repeatable)"
    )
    group = parser.add_argument_group("expected value")
    group.add_argument("-e", "--expect", action="append", metavar="VALUE", help="expected answer (repeatable)")
    group.add_argument("--expect-absent", action="store_true", help="expect the record to be gone (NXDOMAIN or empty)")
    group.add_argument(
        "-a",
        "--authoritative",
        action="store_true",
        help="use the answer of the zone's authoritative name servers as the expected value",
    )
    group.add_argument("--match", choices=MATCH_MODES, default="exact", help="exact set or contains (default: exact)")
    group.add_argument(
        "--threshold",
        type=float,
        default=100.0,
        metavar="PCT",
        help="percent of resolvers that must match (or agree) to pass (default: 100)",
    )
    parser.add_argument("--timeout", type=float, default=3.0, metavar="SECONDS", help="per query timeout (default: 3)")
    parser.add_argument("--workers", type=int, default=32, help="parallel queries (default: 32)")
    _add_selection(parser)
    _add_output(parser)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dns-propagation",
        description="Check DNS propagation across public resolvers, wait for changes, and lint SPF/DMARC/DKIM.",
        epilog="Exit codes: 0 propagated/passed, 1 not propagated/failed, 2 usage error, 3 DNS lookups failed.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    check = sub.add_parser("check", help="query every resolver once and show the propagation table (default)")
    _add_check_options(check)

    watch_p = sub.add_parser("watch", help="repeat the check until the record has propagated")
    _add_check_options(watch_p)
    watch_p.add_argument("--interval", type=float, default=30.0, metavar="SECONDS", help="time between rounds (30)")
    watch_p.add_argument(
        "--max-wait", type=float, default=3600.0, metavar="SECONDS", help="give up after this long (default: 3600)"
    )
    watch_p.add_argument("--table", action="store_true", help="print the full table every round")

    email = sub.add_parser("email", help="check MX, SPF, DMARC, DKIM, MTA-STS and TLS-RPT records of a domain")
    email.add_argument("domain")
    email.add_argument(
        "-s", "--selector", action="append", metavar="SELECTOR", help="DKIM selector (repeatable, comma separated)"
    )
    email.add_argument(
        "--only", action="append", metavar="CHECKS", help="comma separated subset of " + ",".join(EMAIL_CHECKS)
    )
    email.add_argument("--no-recursive-spf", action="store_true", help="do not follow include/redirect for the count")
    email.add_argument(
        "--resolver",
        dest="custom",
        metavar="[NAME=]ADDRESS",
        help="resolver to use (IP or https:// DoH URL, default: Cloudflare 1.1.1.1)",
    )
    email.add_argument("--transport", choices=("udp", "tcp", "doh"), default="udp", help="default: udp")
    email.add_argument("--doh", dest="transport", action="store_const", const="doh", help="use DNS over HTTPS")
    email.add_argument("--tcp", dest="transport", action="store_const", const="tcp", help="use TCP only")
    email.add_argument("--timeout", type=float, default=3.0, metavar="SECONDS")
    _add_output(email)

    res = sub.add_parser("resolvers", help="list the built-in resolvers")
    res.add_argument("--region", action="append", metavar="REGION")
    res.add_argument("--json", action="store_true")
    res.add_argument("--no-color", action="store_true")
    return parser


def _types(args: argparse.Namespace) -> list[str]:
    raw = _csv(args.types) + _csv(args.type_opts)
    types = [check_type(t) for t in raw] or ["A"]
    return list(dict.fromkeys(types))


def _resolvers(args: argparse.Namespace) -> list[Resolver]:
    pool: list[Resolver] = load_file(args.resolvers_file) if args.resolvers_file else list(BUILTIN)
    custom = [parse_custom(spec, i) for i, spec in enumerate(args.custom or (), start=1)]
    ids = _csv(args.resolvers)
    regions = _csv(args.region)
    exclude = ("filtering",) if args.no_filtering else ()
    if custom and not ids and not regions and not args.resolvers_file:
        return custom
    return select(ids, regions, exclude, pool) + custom


def _style(args: argparse.Namespace, stream: TextIO) -> Style:
    enabled = not args.no_color and not os.environ.get("NO_COLOR") and getattr(stream, "isatty", lambda: False)()
    return Style(bool(enabled))


def _default_via(transport: str) -> Target:
    cloudflare = BUILTIN[0]
    return Target(cloudflare, transport if transport in ("doh", "tcp") else "udp")


def _prepare(args: argparse.Namespace, querier: Querier) -> Callable[[], list[Report]]:
    types = _types(args)
    if args.threshold <= 0 or args.threshold > 100:
        raise UsageError("--threshold must be between 0 and 100")
    if args.timeout <= 0:
        raise UsageError("--timeout must be positive")
    given = sum(bool(x) for x in (args.expect, args.expect_absent, args.authoritative))
    if given > 1:
        raise UsageError("use only one of --expect, --expect-absent and --authoritative")
    if args.expect and len(types) > 1:
        raise UsageError("--expect works with one record type at a time")
    targets = targets_for(_resolvers(args), args.transport)
    if not targets:
        raise UsageError("no resolvers left after filtering (DoH-only resolvers need --doh)")

    fixed: dict[str, Expectation | None] = {}
    for rdtype in types:
        if args.expect:
            fixed[rdtype] = Expectation.build(rdtype, _csv(args.expect) if rdtype != "TXT" else args.expect, args.match)
        elif args.expect_absent:
            fixed[rdtype] = Expectation((), True, args.match)
        else:
            fixed[rdtype] = None

    def run() -> list[Report]:
        reports = []
        for rdtype in types:
            expectation = fixed[rdtype]
            notes: list[str] = []
            if args.authoritative:
                expectation, auth_report = expectation_from_authoritative(
                    args.name, rdtype, querier, _default_via(args.transport), mode=args.match, timeout=args.timeout
                )
                notes.extend(auth_report.notes)
            report = run_check(
                args.name,
                rdtype,
                targets,
                querier,
                expectation,
                timeout=args.timeout,
                threshold=args.threshold,
                workers=args.workers,
            )
            report.notes.extend(notes)
            reports.append(report)
        return reports

    return run


def _exit_code(reports: Sequence[Report]) -> int:
    if any(r.responded == 0 for r in reports):
        return EXIT_DNS_FAILURE
    return EXIT_OK if all(r.propagated for r in reports) else EXIT_NOT_PROPAGATED


def cmd_check(args: argparse.Namespace, querier: Querier, out: TextIO) -> int:
    reports = _prepare(args, querier)()
    if args.json:
        print(to_json(reports_document(reports)), file=out)
    else:
        style = _style(args, out)
        print("\n\n".join(render_report(r, style, args.wide) for r in reports), file=out)
    return _exit_code(reports)


def cmd_watch(
    args: argparse.Namespace, querier: Querier, out: TextIO, sleep: Callable[[float], None], clock: Callable[[], float]
) -> int:
    if args.interval <= 0 or args.max_wait < 0:
        raise UsageError("--interval must be positive and --max-wait not negative")
    run = _prepare(args, querier)
    style = _style(args, out)

    def on_round(n: int, reports: list[Report]) -> None:
        if args.json:
            return
        if args.table:
            print("\n\n".join(render_report(r, style, args.wide) for r in reports), file=out)
        print(render_round(n, reports, style), file=out, flush=True)

    propagated, reports, rounds = watch(
        run, interval=args.interval, max_wait=args.max_wait, on_round=on_round, sleep=sleep, clock=clock
    )
    if args.json:
        print(to_json(reports_document(reports, rounds=rounds)), file=out)
    elif not args.table:
        print("", file=out)
        print("\n\n".join(render_report(r, style, args.wide) for r in reports), file=out)
    if not args.json:
        message = "propagated" if propagated else f"not propagated after {rounds} round(s)"
        print(style(message, "green" if propagated else "red"), file=out)
    if propagated:
        return EXIT_OK
    return EXIT_DNS_FAILURE if any(r.responded == 0 for r in reports) else EXIT_NOT_PROPAGATED


def cmd_email(args: argparse.Namespace, querier: Querier, out: TextIO) -> int:
    resolver = parse_custom(args.custom) if args.custom else BUILTIN[0]
    if resolver.doh and not resolver.address:
        target = Target(resolver, "doh")
    elif not resolver.supports(args.transport):
        raise UsageError(f"{resolver.name} cannot be used with --transport {args.transport}")
    else:
        target = Target(resolver, args.transport)
    checks = _csv(args.only) or list(EMAIL_CHECKS)
    unknown = sorted(set(checks) - set(EMAIL_CHECKS))
    if unknown:
        raise UsageError(f"unknown check(s): {', '.join(unknown)}")

    def lookup(name: str, rdtype: str) -> QueryResult:
        return querier(target, name, rdtype, args.timeout)

    report = check_domain(
        lookup, args.domain, _csv(args.selector), checks=checks, recursive_spf=not args.no_recursive_spf
    )
    if args.json:
        print(to_json({"tool": "dns-propagation", "version": __version__, **report.to_dict()}), file=out)
    else:
        print(render_email(report, _style(args, out)), file=out)
    if report.lookups and report.lookup_failures == report.lookups:
        return EXIT_DNS_FAILURE
    return EXIT_OK if report.errors == 0 else EXIT_NOT_PROPAGATED


def cmd_resolvers(args: argparse.Namespace, out: TextIO) -> int:
    resolvers = select((), _csv(args.region))
    if args.json:
        rows = [
            {
                "id": r.id,
                "name": r.name,
                "provider": r.provider,
                "region": r.region,
                "country": r.country,
                "address": r.address,
                "doh": r.doh,
                "tags": list(r.tags),
            }
            for r in resolvers
        ]
        print(to_json(rows), file=out)
    else:
        print(render_resolvers(resolvers, _style(args, out)), file=out)
    return EXIT_OK


def main(
    argv: Sequence[str] | None = None,
    *,
    querier: Querier | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    out = out or sys.stdout
    err = err or sys.stderr
    if argv and argv[0] not in COMMANDS and not argv[0].startswith("-"):
        argv.insert(0, "check")
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    if args.command is None:
        parser.print_help(file=out)
        return EXIT_USAGE
    querier = querier or DnsQuerier()
    try:
        if args.command == "check":
            return cmd_check(args, querier, out)
        if args.command == "watch":
            return cmd_watch(args, querier, out, sleep, clock)
        if args.command == "email":
            return cmd_email(args, querier, out)
        return cmd_resolvers(args, out)
    except (UsageError, ResolverError, ValueError) as exc:
        print(f"dns-propagation: error: {exc}", file=err)
        return EXIT_USAGE
    except CheckError as exc:
        print(f"dns-propagation: {exc}", file=err)
        return EXIT_DNS_FAILURE
    except KeyboardInterrupt:
        print("interrupted", file=err)
        return 130
