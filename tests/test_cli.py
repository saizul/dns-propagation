import io
import json

import pytest

from conftest import EMPTY, TIMEOUT, FakeQuerier, ok
from dns_propagation import __version__
from dns_propagation.cli import EXIT_DNS_FAILURE, EXIT_NOT_PROPAGATED, EXIT_OK, EXIT_USAGE, main


def run(argv, querier=None, **kwargs):
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, querier=querier or FakeQuerier(), out=out, err=err, **kwargs)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def everywhere():
    fake = FakeQuerier()
    fake.set("*", "example.com", "A", ok("192.0.2.10"))
    return fake


def test_version(capsys):
    assert main(["--version"]) == 0
    assert __version__ in capsys.readouterr().out


def test_default_command_is_check(everywhere):
    code, out, _ = run(["example.com", "-r", "cloudflare,google-2"], everywhere)
    assert code == EXIT_OK
    assert "Cloudflare" in out and "Google secondary" in out
    assert "Consistency: 100%" in out
    assert {c[0] for c in everywhere.calls} == {"1.1.1.1", "8.8.4.4"}


def test_check_with_expected_value_json(everywhere):
    everywhere.set("8.8.8.8", "example.com", "A", ok("198.51.100.1"))
    code, out, _ = run(
        ["check", "example.com", "A", "-r", "cloudflare,cloudflare-2,google,google-2", "-e", "192.0.2.10", "--json"],
        everywhere,
    )
    assert code == EXIT_NOT_PROPAGATED
    doc = json.loads(out)
    assert doc["tool"] == "dns-propagation" and doc["propagated"] is False
    summary = doc["checks"][0]["summary"]
    assert summary["matching"] == 3 and summary["propagation_pct"] == 75.0
    assert [r["matches"] for r in doc["checks"][0]["resolvers"]] == [True, True, False, True]

    code, _, _ = run(
        [
            "example.com",
            "-r",
            "cloudflare,cloudflare-2,google,google-2",
            "-e",
            "192.0.2.10",
            "--threshold",
            "75",
            "--json",
        ],
        everywhere,
    )
    assert code == EXIT_OK


def test_multiple_types(everywhere):
    everywhere.set("*", "example.com", "AAAA", ok("2001:db8::10"))
    code, out, _ = run(["example.com", "A", "-t", "aaaa", "-r", "quad9", "--json"], everywhere)
    assert code == EXIT_OK
    assert [c["type"] for c in json.loads(out)["checks"]] == ["A", "AAAA"]


def test_all_failed_is_exit_3():
    fake = FakeQuerier({("*", "example.com", "A"): TIMEOUT})
    code, out, _ = run(["example.com", "-r", "cloudflare"], fake)
    assert code == EXIT_DNS_FAILURE
    assert "No resolver answered" in out


@pytest.mark.parametrize(
    "argv",
    [
        ["example.com", "BOGUS"],
        ["example.com", "A", "AAAA", "-e", "192.0.2.1"],
        ["example.com", "-e", "192.0.2.1", "--expect-absent"],
        ["example.com", "-e", "not-an-ip"],
        ["example.com", "--threshold", "0"],
        ["example.com", "-r", "nope"],
        ["example.com", "--resolver", "dns.example.com"],
        ["example.com", "--region", "mars"],
        ["check", "example.com", "--transport", "carrier-pigeon"],
        ["email", "example.com", "--only", "spf,bimi"],
    ],
)
def test_usage_errors(argv):
    code, _, _ = run(argv)
    assert code == EXIT_USAGE


def test_custom_resolvers_replace_the_builtin_list():
    fake = FakeQuerier({("*", "example.com", "A"): ok("192.0.2.10")})
    code, out, _ = run(["example.com", "--resolver", "office=10.0.0.53", "--resolver", "203.0.113.53"], fake)
    assert code == EXIT_OK
    assert [c[0] for c in fake.calls] == ["10.0.0.53", "203.0.113.53"]
    assert "office" in out


def test_resolvers_file(tmp_path, everywhere):
    path = tmp_path / "r.txt"
    path.write_text("lan 10.0.0.53 lan\n", encoding="utf-8")
    code, _, _ = run(["example.com", "--resolvers-file", str(path)], everywhere)
    assert code == EXIT_OK
    assert [c[0] for c in everywhere.calls] == ["10.0.0.53"]


def test_doh_and_no_filtering(everywhere):
    code, out, _ = run(["example.com", "--doh", "--no-filtering", "--json"], everywhere)
    assert code == EXIT_OK
    resolvers = json.loads(out)["checks"][0]["resolvers"]
    assert all(r["transport"] == "doh" and r["endpoint"].startswith("https://") for r in resolvers)
    assert "quad9" not in {r["id"] for r in resolvers}
    assert "mullvad" in {r["id"] for r in resolvers}


def test_authoritative_expectation():
    fake = FakeQuerier(
        {
            ("1.1.1.1", "example.com", "NS"): ok("ns1.example.net."),
            ("1.1.1.1", "ns1.example.net", "A"): ok("203.0.113.1"),
            ("203.0.113.1", "example.com", "TXT"): ok("v=spf1 -all", "site-verification=new"),
            ("*", "example.com", "TXT"): ok("v=spf1 -all"),
        }
    )
    code, out, _ = run(["example.com", "TXT", "-a", "-r", "google", "--json"], fake)
    assert code == EXIT_NOT_PROPAGATED
    check = json.loads(out)["checks"][0]
    assert check["expected"]["source"] == "authoritative"
    assert check["expected"]["values"] == ["site-verification=new", "v=spf1 -all"]


def test_watch_exits_when_propagated():
    fake = FakeQuerier({("*", "example.com", "A"): lambda n: ok("192.0.2.10") if n >= 2 else EMPTY})
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        fake.round += 1

    fake.round = 1
    code, out, _ = run(
        ["watch", "example.com", "-e", "192.0.2.10", "-r", "cloudflare", "--interval", "5"],
        fake,
        sleep=sleep,
        clock=lambda: 0.0,
    )
    assert code == EXIT_OK
    assert sleeps == [5.0]
    assert "round 1:" in out and "round 2:" in out and "propagated" in out


def test_watch_times_out_json():
    fake = FakeQuerier({("*", "example.com", "A"): ok("198.51.100.1")})
    now = [0.0]

    def sleep(seconds):
        now[0] += seconds

    code, out, _ = run(
        [
            "watch",
            "example.com",
            "-e",
            "192.0.2.10",
            "-r",
            "cloudflare",
            "--interval",
            "10",
            "--max-wait",
            "25",
            "--json",
        ],
        fake,
        sleep=sleep,
        clock=lambda: now[0],
    )
    assert code == EXIT_NOT_PROPAGATED
    doc = json.loads(out)
    assert doc["rounds"] == 3 and doc["propagated"] is False


def test_email_command():
    fake = FakeQuerier(
        {
            ("1.1.1.1", "example.com", "MX"): ok("10 mx.example.com."),
            ("1.1.1.1", "example.com", "TXT"): ok("v=spf1 +all"),
            ("1.1.1.1", "_dmarc.example.com", "TXT"): ok("v=DMARC1; p=reject; rua=mailto:d@example.com"),
        }
    )
    code, out, _ = run(["email", "example.com", "--only", "mx,spf,dmarc", "--no-color"], fake)
    assert code == EXIT_NOT_PROPAGATED
    assert "allows every server" in out and "Result: failed" in out

    code, out, _ = run(["email", "example.com", "--only", "dmarc", "--json"], fake)
    assert code == EXIT_OK
    assert json.loads(out)["summary"]["passed"] is True


def test_email_with_custom_doh_resolver():
    fake = FakeQuerier({("*", "_dmarc.example.com", "TXT"): ok("v=DMARC1; p=reject; rua=mailto:d@example.com")})
    code, _, _ = run(["email", "example.com", "--only", "dmarc", "--resolver", "https://doh.example/dns-query"], fake)
    assert code == EXIT_OK
    assert fake.calls[0][:2] == ("https://doh.example/dns-query", "doh")


def test_email_all_lookups_failed():
    fake = FakeQuerier({("*", "example.com", "MX"): TIMEOUT, ("*", "example.com", "TXT"): TIMEOUT})
    code, _, _ = run(["email", "example.com", "--only", "mx,spf"], fake)
    assert code == EXIT_DNS_FAILURE


def test_resolvers_command():
    code, out, _ = run(["resolvers", "--json", "--region", "eu"])
    assert code == EXIT_OK
    rows = json.loads(out)
    assert rows and all(r["region"] == "eu" or r["country"].lower() == "eu" for r in rows)
    code, out, _ = run(["resolvers"])
    assert "cloudflare" in out and "DOH" in out


def test_no_command_prints_help():
    code, out, _ = run([])
    assert code == EXIT_USAGE and "COMMAND" in out


def test_color_is_off_for_non_tty(everywhere):
    _, out, _ = run(["example.com", "-r", "cloudflare"], everywhere)
    assert "\033[" not in out
