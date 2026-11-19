"""Sending one query to one resolver and turning the response into a result."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Protocol

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype

from .records import normalize_rdata
from .resolvers import Target

# Statuses where the resolver answered (as opposed to timeouts and network errors).
ANSWERED = ("ok", "nxdomain", "noanswer", "servfail", "refused")
FAILED = ("timeout", "error")


@dataclass(frozen=True)
class QueryResult:
    status: str
    answers: tuple[str, ...] = field(default_factory=tuple)
    ttl: int | None = None
    rcode: str = ""
    elapsed_ms: float = 0.0
    error: str = ""

    @property
    def responded(self) -> bool:
        return self.status in ANSWERED


class Querier(Protocol):
    def __call__(self, target: Target, name: str, rdtype: str, timeout: float) -> QueryResult: ...


def parse_response(response: dns.message.Message, rdtype: str, elapsed_ms: float = 0.0) -> QueryResult:
    """Extract normalised answers of ``rdtype`` from a DNS response."""
    rcode = dns.rcode.to_text(response.rcode())
    if rcode == "NXDOMAIN":
        return QueryResult("nxdomain", rcode=rcode, elapsed_ms=elapsed_ms)
    if rcode == "SERVFAIL":
        return QueryResult("servfail", rcode=rcode, elapsed_ms=elapsed_ms)
    if rcode == "REFUSED":
        return QueryResult("refused", rcode=rcode, elapsed_ms=elapsed_ms)
    if rcode != "NOERROR":
        return QueryResult("error", rcode=rcode, elapsed_ms=elapsed_ms, error=f"rcode {rcode}")
    wanted = dns.rdatatype.from_text(rdtype)
    answers: set[str] = set()
    ttl: int | None = None
    for rrset in response.answer:
        if rrset.rdtype != wanted:
            continue
        ttl = rrset.ttl if ttl is None else min(ttl, rrset.ttl)
        for rdata in rrset:
            answers.add(normalize_rdata(rdtype, rdata))
    if not answers:
        return QueryResult("noanswer", rcode=rcode, elapsed_ms=elapsed_ms)
    return QueryResult("ok", tuple(sorted(answers)), ttl, rcode, elapsed_ms)


class DnsQuerier:
    """Real network querier: UDP with TCP fallback, TCP only, or DNS over HTTPS."""

    def __call__(self, target: Target, name: str, rdtype: str, timeout: float) -> QueryResult:
        try:
            qname = dns.name.from_text(name)
        except (dns.exception.DNSException, ValueError) as exc:
            return QueryResult("error", error=f"invalid name: {exc}")
        query = dns.message.make_query(qname, rdtype)
        if not target.recursion:
            query.flags &= ~dns.flags.RD
        start = time.perf_counter()
        try:
            if target.transport == "doh":
                response = dns.query.https(query, target.endpoint, timeout=timeout)
            elif target.transport == "tcp":
                response = dns.query.tcp(query, target.endpoint, timeout=timeout)
            else:
                response, _ = dns.query.udp_with_fallback(query, target.endpoint, timeout=timeout)
        except dns.exception.Timeout:
            return QueryResult("timeout", elapsed_ms=_ms(start), error=f"no answer within {timeout:g}s")
        except Exception as exc:  # network errors, TLS errors, malformed responses
            message = str(exc) or exc.__class__.__name__
            if "timed out" in message.lower():
                return QueryResult("timeout", elapsed_ms=_ms(start), error=message)
            return QueryResult("error", elapsed_ms=_ms(start), error=message)
        return parse_response(response, rdtype, _ms(start))


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 1)
