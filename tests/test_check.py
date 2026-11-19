import pytest

from conftest import EMPTY, NX, TIMEOUT, FakeQuerier, make_targets, ok
from dns_propagation.check import (
    CheckError,
    Expectation,
    expectation_from_authoritative,
    find_authoritative,
    run_check,
    watch,
)
from dns_propagation.query import QueryResult
from dns_propagation.resolvers import BUILTIN, Target


def test_all_resolvers_agree(fake, three_targets):
    fake.set("*", "example.com", "A", ok("192.0.2.10"))
    report = run_check("Example.COM.", "a", three_targets, fake)
    assert report.name == "example.com" and report.rdtype == "A"
    assert report.consistency_pct == 100.0
    assert report.majority == ("ok", ("192.0.2.10",))
    assert report.propagated
    assert report.propagation_pct is None
    assert len(fake.calls) == 3


def test_partial_propagation_with_expected(fake, three_targets):
    fake.set("*", "example.com", "A", ok("192.0.2.10"))
    fake.set("192.0.2.3", "example.com", "A", ok("198.51.100.1"))
    expectation = Expectation.build("A", ["192.0.2.10"])
    report = run_check("example.com", "A", three_targets, fake, expectation)
    assert [r.matches for r in report.results] == [True, True, False]
    assert report.matching == 2
    assert report.propagation_pct == pytest.approx(66.7)
    assert not report.propagated
    lenient = run_check("example.com", "A", three_targets, fake, expectation, threshold=60)
    assert lenient.propagated


def test_results_keep_target_order(fake):
    targets = make_targets(*(f"192.0.2.{i}" for i in range(1, 21)))
    for i in range(1, 21):
        fake.set(f"192.0.2.{i}", "example.com", "TXT", ok(f"r{i}"))
    report = run_check("example.com", "TXT", targets, fake, workers=8)
    assert [r.result.answers[0] for r in report.results] == [f"r{i}" for i in range(1, 21)]


def test_timeouts_count_against_propagation_but_not_consistency(fake, three_targets):
    fake.set("*", "example.com", "A", ok("192.0.2.10"))
    fake.set("192.0.2.2", "example.com", "A", TIMEOUT)
    report = run_check("example.com", "A", three_targets, fake, Expectation.build("A", ["192.0.2.10"]))
    assert report.responded == 2
    assert report.consistency_pct == 100.0
    assert report.propagation_pct == pytest.approx(66.7)
    assert report.to_dict()["resolvers"][1]["status"] == "timeout"


def test_no_answers_at_all(fake, three_targets):
    fake.set("*", "example.com", "A", TIMEOUT)
    report = run_check("example.com", "A", three_targets, fake)
    assert report.responded == 0
    assert report.majority is None
    assert report.consistency_pct == 0.0
    assert not report.propagated


def test_expect_absent(fake, three_targets):
    fake.set("*", "old.example.com", "A", NX)
    fake.set("192.0.2.2", "old.example.com", "A", EMPTY)
    fake.set("192.0.2.3", "old.example.com", "A", ok("192.0.2.99"))
    report = run_check("old.example.com", "A", three_targets, fake, Expectation((), True))
    assert [r.matches for r in report.results] == [True, True, False]


def test_querier_exception_becomes_error(three_targets):
    def broken(target, name, rdtype, timeout):
        raise OSError("network unreachable")

    report = run_check("example.com", "A", three_targets, broken)
    assert {r.result.status for r in report.results} == {"error"}
    assert report.results[0].result.error == "network unreachable"


def test_invalid_input(fake, three_targets):
    with pytest.raises(ValueError):
        run_check("exa mple.com", "A", three_targets, fake)
    with pytest.raises(ValueError):
        run_check("example.com", "PTRX", three_targets, fake)
    with pytest.raises(CheckError):
        run_check("example.com", "A", [], fake)
    with pytest.raises(ValueError):
        Expectation.build("A", [])


def test_majority_tie_prefers_real_answers(fake):
    targets = make_targets("192.0.2.1", "192.0.2.2")
    fake.set("192.0.2.1", "example.com", "A", NX)
    fake.set("192.0.2.2", "example.com", "A", ok("192.0.2.10"))
    report = run_check("example.com", "A", targets, fake)
    assert report.majority == ("ok", ("192.0.2.10",))
    assert report.consistency_pct == 50.0


def test_report_json_shape(fake, three_targets):
    fake.set("*", "example.com", "MX", ok("10 mx.example.com."))
    data = run_check("example.com", "MX", three_targets, fake, Expectation.build("MX", ["mx.example.com"])).to_dict()
    assert data["expected"] == {"values": ["* mx.example.com."], "absent": False, "mode": "exact", "source": "cli"}
    assert data["summary"]["propagated"] is True
    assert data["summary"]["propagation_pct"] == 100.0
    assert set(data["resolvers"][0]) >= {"id", "endpoint", "status", "answers", "ttl", "matches", "transport"}


# --------------------------------------------------------------------------- authoritative

VIA = Target(BUILTIN[0])


def zone_with_ns(fake: FakeQuerier) -> None:
    fake.set("1.1.1.1", "www.example.com", "NS", EMPTY)
    fake.set("1.1.1.1", "example.com", "NS", ok("ns1.example.net.", "ns2.example.net."))
    fake.set("1.1.1.1", "ns1.example.net", "A", ok("203.0.113.1"))
    fake.set("1.1.1.1", "ns2.example.net", "A", EMPTY)
    fake.set("1.1.1.1", "ns2.example.net", "AAAA", ok("2001:db8::2"))


def test_find_authoritative_walks_up_to_the_zone(fake):
    zone_with_ns(fake)
    targets = find_authoritative("www.example.com", fake, VIA)
    assert [t.endpoint for t in targets] == ["203.0.113.1", "2001:db8::2"]
    assert all(not t.recursion for t in targets)
    assert targets[0].resolver.provider == "authoritative"


def test_find_authoritative_errors(fake):
    with pytest.raises(CheckError, match="no NS records"):
        find_authoritative("nothing.example", fake, VIA)
    fake.set("1.1.1.1", "x.example", "NS", TIMEOUT)
    with pytest.raises(CheckError, match="could not look up"):
        find_authoritative("x.example", fake, VIA)
    fake.set("1.1.1.1", "y.example", "NS", ok("ns.y.example."))
    with pytest.raises(CheckError, match="addresses"):
        find_authoritative("y.example", fake, VIA)


def test_expectation_from_authoritative(fake):
    zone_with_ns(fake)
    fake.set("203.0.113.1", "www.example.com", "A", ok("192.0.2.80"))
    fake.set("2001:db8::2", "www.example.com", "A", ok("192.0.2.80"))
    expectation, report = expectation_from_authoritative("www.example.com", "A", fake, VIA)
    assert expectation.values == ("192.0.2.80",)
    assert expectation.source == "authoritative"
    assert report.notes == []
    assert ("203.0.113.1", "udp", "www.example.com", "A", False) in fake.calls


def test_expectation_from_authoritative_absent_and_disagreement(fake):
    zone_with_ns(fake)
    fake.set("203.0.113.1", "www.example.com", "TXT", NX)
    fake.set("2001:db8::2", "www.example.com", "TXT", NX)
    expectation, _ = expectation_from_authoritative("www.example.com", "TXT", fake, VIA)
    assert expectation.absent

    fake.set("203.0.113.1", "www.example.com", "A", ok("192.0.2.1"))
    fake.set("2001:db8::2", "www.example.com", "A", ok("192.0.2.2"))
    _, report = expectation_from_authoritative("www.example.com", "A", fake, VIA)
    assert report.notes and "disagree" in report.notes[0]


def test_expectation_from_authoritative_servfail(fake):
    zone_with_ns(fake)
    fake.set("*", "www.example.com", "A", QueryResult("servfail", rcode="SERVFAIL"))
    with pytest.raises(CheckError, match="SERVFAIL"):
        expectation_from_authoritative("www.example.com", "A", fake, VIA)


# --------------------------------------------------------------------------- watch


class Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def test_watch_until_propagated(fake, three_targets):
    clock = Clock()
    fake.set("*", "example.com", "A", lambda n: ok("192.0.2.10") if n >= 3 else ok("198.51.100.1"))
    expectation = Expectation.build("A", ["192.0.2.10"])
    seen = []

    def run():
        fake.round += 1
        return [run_check("example.com", "A", three_targets, fake, expectation)]

    done, reports, rounds = watch(
        run, interval=30, max_wait=600, on_round=lambda n, r: seen.append(n), sleep=clock.sleep, clock=clock
    )
    assert done and rounds == 3 and seen == [1, 2, 3]
    assert clock.sleeps == [30, 30]
    assert reports[0].propagated


def test_watch_gives_up(fake, three_targets):
    clock = Clock()
    fake.set("*", "example.com", "A", ok("198.51.100.1"))
    expectation = Expectation.build("A", ["192.0.2.10"])
    done, _, rounds = watch(
        lambda: [run_check("example.com", "A", three_targets, fake, expectation)],
        interval=60,
        max_wait=150,
        sleep=clock.sleep,
        clock=clock,
    )
    assert not done
    assert rounds == 3
    assert clock.now == 120
