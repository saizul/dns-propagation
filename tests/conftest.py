"""Shared fixtures. Nothing here touches the network."""

from __future__ import annotations

import threading
from collections.abc import Callable

import pytest

from dns_propagation.query import QueryResult
from dns_propagation.resolvers import Resolver, Target


def ok(*answers: str, ttl: int = 300) -> QueryResult:
    return QueryResult("ok", tuple(sorted(answers)), ttl, "NOERROR", 12.0)


NX = QueryResult("nxdomain", rcode="NXDOMAIN", elapsed_ms=5.0)
EMPTY = QueryResult("noanswer", rcode="NOERROR", elapsed_ms=5.0)
TIMEOUT = QueryResult("timeout", elapsed_ms=3000.0, error="no answer within 3s")


class FakeQuerier:
    """Answers from a table instead of the network.

    Keys are ``(endpoint, name, type)``; ``("*", name, type)`` is the fallback for every
    resolver. Unknown questions get NXDOMAIN. A callable value is called with the round number.
    """

    def __init__(self, table: dict[tuple[str, str, str], QueryResult | Callable[[int], QueryResult]] | None = None):
        self.table = dict(table or {})
        self.calls: list[tuple[str, str, str, str, bool]] = []
        self.round = 0
        self._lock = threading.Lock()

    def set(self, endpoint: str, name: str, rdtype: str, result: QueryResult | Callable[[int], QueryResult]) -> None:
        self.table[(endpoint, name, rdtype)] = result

    def __call__(self, target: Target, name: str, rdtype: str, timeout: float) -> QueryResult:
        with self._lock:
            self.calls.append((target.endpoint, target.transport, name, rdtype, target.recursion))
        value = self.table.get((target.endpoint, name, rdtype), self.table.get(("*", name, rdtype), NX))
        return value(self.round) if callable(value) else value


@pytest.fixture
def fake() -> FakeQuerier:
    return FakeQuerier()


def make_targets(*addresses: str) -> list[Target]:
    return [
        Target(Resolver(f"r{i}", f"Resolver {i}", "test", "global", "", address)) for i, address in enumerate(addresses)
    ]


@pytest.fixture
def three_targets() -> list[Target]:
    return make_targets("192.0.2.1", "192.0.2.2", "192.0.2.3")
