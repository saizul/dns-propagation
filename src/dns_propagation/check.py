"""Concurrent propagation checks, summaries, authoritative baselines and watch mode."""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from .query import Querier, QueryResult
from .records import MATCH_MODES, answers_match, check_type, normalize_expected
from .resolvers import Resolver, Target


class CheckError(RuntimeError):
    """A check could not be set up (for example no authoritative servers found)."""


@dataclass(frozen=True)
class Expectation:
    """What a propagated answer looks like."""

    values: tuple[str, ...] = ()
    absent: bool = False
    mode: str = "exact"
    source: str = "cli"

    @classmethod
    def build(cls, rdtype: str, values: Iterable[str], mode: str = "exact", source: str = "cli") -> Expectation:
        if mode not in MATCH_MODES:
            raise ValueError(f"unknown match mode {mode!r}")
        normalized: list[str] = []
        for value in values:
            item = normalize_expected(rdtype, value)
            if item not in normalized:
                normalized.append(item)
        if not normalized:
            raise ValueError("no expected values")
        return cls(tuple(normalized), False, mode, source)

    def matches(self, rdtype: str, result: QueryResult) -> bool:
        if self.absent:
            return result.status in ("nxdomain", "noanswer")
        return result.status == "ok" and answers_match(rdtype, result.answers, self.values, self.mode)

    def describe(self) -> str:
        if self.absent:
            return "no record (NXDOMAIN or empty answer)"
        return ", ".join(self.values) + ("" if self.mode == "exact" else " (contains)")

    def to_dict(self) -> dict[str, Any]:
        return {"values": list(self.values), "absent": self.absent, "mode": self.mode, "source": self.source}


@dataclass(frozen=True)
class ResolverResult:
    target: Target
    result: QueryResult
    matches: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        r = self.target.resolver
        return {
            "id": r.id,
            "name": r.name,
            "provider": r.provider,
            "region": r.region,
            "country": r.country,
            "transport": self.target.transport,
            "endpoint": self.target.endpoint,
            "status": self.result.status,
            "rcode": self.result.rcode,
            "answers": list(self.result.answers),
            "ttl": self.result.ttl,
            "elapsed_ms": self.result.elapsed_ms,
            "error": self.result.error,
            "matches": self.matches,
        }


def _signature(result: QueryResult) -> tuple[str, tuple[str, ...]]:
    return result.status, result.answers


@dataclass
class Report:
    name: str
    rdtype: str
    results: list[ResolverResult]
    expectation: Expectation | None = None
    threshold: float = 100.0
    notes: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def responded(self) -> int:
        return sum(1 for r in self.results if r.result.responded)

    @property
    def matching(self) -> int:
        return sum(1 for r in self.results if r.matches)

    @property
    def propagation_pct(self) -> float | None:
        if self.expectation is None or not self.total:
            return None
        return round(self.matching * 100 / self.total, 1)

    @property
    def majority(self) -> tuple[str, tuple[str, ...]] | None:
        groups = Counter(_signature(r.result) for r in self.results if r.result.responded)
        if not groups:
            return None
        # Most common answer; ties are broken by preferring real answers, then by text.
        return max(groups.items(), key=lambda item: (item[1], item[0][0] == "ok", item[0]))[0]

    @property
    def consistency_pct(self) -> float:
        if not self.responded:
            return 0.0
        majority = self.majority
        agreeing = sum(1 for r in self.results if r.result.responded and _signature(r.result) == majority)
        return round(agreeing * 100 / self.responded, 1)

    @property
    def propagated(self) -> bool:
        if not self.responded:
            return False
        if self.expectation is not None:
            pct = self.propagation_pct or 0.0
            return pct >= self.threshold
        return self.consistency_pct >= self.threshold

    def to_dict(self) -> dict[str, Any]:
        majority = self.majority
        return {
            "name": self.name,
            "type": self.rdtype,
            "expected": self.expectation.to_dict() if self.expectation else None,
            "threshold": self.threshold,
            "resolvers": [r.to_dict() for r in self.results],
            "summary": {
                "total": self.total,
                "responded": self.responded,
                "matching": self.matching if self.expectation else None,
                "propagation_pct": self.propagation_pct,
                "consistency_pct": self.consistency_pct,
                "majority": {"status": majority[0], "answers": list(majority[1])} if majority else None,
                "propagated": self.propagated,
            },
            "notes": list(self.notes),
        }


def clean_name(name: str) -> str:
    name = name.strip().rstrip(".").lower()
    if not name or " " in name or len(name) > 253:
        raise ValueError(f"invalid domain name {name!r}")
    return name


def run_check(
    name: str,
    rdtype: str,
    targets: Sequence[Target],
    querier: Querier,
    expectation: Expectation | None = None,
    *,
    timeout: float = 3.0,
    threshold: float = 100.0,
    workers: int = 32,
) -> Report:
    """Query every target concurrently and build a report (results keep target order)."""
    name = clean_name(name)
    rdtype = check_type(rdtype)
    if not targets:
        raise CheckError("no resolvers selected")

    def one(target: Target) -> ResolverResult:
        try:
            result = querier(target, name, rdtype, timeout)
        except Exception as exc:  # a querier must never break the whole run
            result = QueryResult("error", error=str(exc) or exc.__class__.__name__)
        matches = expectation.matches(rdtype, result) if expectation else None
        return ResolverResult(target, result, matches)

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets)))) as pool:
        results = list(pool.map(one, targets))
    return Report(name, rdtype, results, expectation, threshold)


def find_authoritative(name: str, querier: Querier, via: Target, timeout: float = 3.0) -> list[Target]:
    """Find the zone's authoritative name servers (via a recursive resolver) as targets."""
    labels = clean_name(name).split(".")
    servers: tuple[str, ...] = ()
    for i in range(len(labels) - 1):
        zone = ".".join(labels[i:])
        result = querier(via, zone, "NS", timeout)
        if result.status == "ok":
            servers = result.answers
            break
        if not result.responded:
            raise CheckError(
                f"could not look up NS records for {zone} via {via.label}: {result.error or result.status}"
            )
    if not servers:
        raise CheckError(f"no NS records found for {name} or its parent zones")
    targets: list[Target] = []
    for host in servers:
        for family in ("A", "AAAA"):
            addr = querier(via, host.rstrip("."), family, timeout)
            if addr.status == "ok":
                ip = addr.answers[0]
                resolver = Resolver(f"auth:{host.rstrip('.')}", host.rstrip("."), "authoritative", "auth", address=ip)
                targets.append(Target(resolver, "tcp" if via.transport == "tcp" else "udp", recursion=False))
                break
    if not targets:
        raise CheckError("could not resolve the addresses of the authoritative name servers")
    return targets


def expectation_from_authoritative(
    name: str,
    rdtype: str,
    querier: Querier,
    via: Target,
    *,
    mode: str = "exact",
    timeout: float = 3.0,
) -> tuple[Expectation, Report]:
    """Use the majority answer of the authoritative servers as the expected value."""
    auth_targets = find_authoritative(name, querier, via, timeout)
    report = run_check(name, rdtype, auth_targets, querier, timeout=timeout)
    majority = report.majority
    if majority is None:
        raise CheckError("none of the authoritative name servers answered")
    status, answers = majority
    if status == "ok":
        expectation = Expectation(answers, False, mode, "authoritative")
    elif status in ("nxdomain", "noanswer"):
        expectation = Expectation((), True, mode, "authoritative")
    else:
        raise CheckError(f"authoritative name servers answered {status.upper()}")
    if report.consistency_pct < 100:
        report.notes.append(
            f"authoritative servers disagree ({report.consistency_pct}% consistent); using the majority"
        )
    return expectation, report


def watch(
    run: Callable[[], list[Report]],
    *,
    interval: float,
    max_wait: float,
    on_round: Callable[[int, list[Report]], None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[bool, list[Report], int]:
    """Repeat ``run`` until every report is propagated or ``max_wait`` seconds pass.

    Returns ``(propagated, last_reports, rounds)``.
    """
    start = clock()
    rounds = 0
    while True:
        rounds += 1
        reports = run()
        if on_round is not None:
            on_round(rounds, reports)
        if reports and all(r.propagated for r in reports):
            return True, reports, rounds
        if clock() - start + interval > max_wait:
            return False, reports, rounds
        sleep(interval)
