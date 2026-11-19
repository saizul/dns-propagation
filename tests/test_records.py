import dns.message
import pytest

from dns_propagation.query import parse_response
from dns_propagation.records import answers_match, check_type, normalize_expected


def response(text: str) -> dns.message.Message:
    return dns.message.from_text(text)


def answer(rdtype: str, *rdata: str, name: str = "example.com.", ttl: int = 300, rcode: str = "NOERROR"):
    lines = [f"{name} {ttl} IN {rdtype} {r}" for r in rdata]
    return response(
        f"id 1\nopcode QUERY\nrcode {rcode}\nflags QR RD RA\n;QUESTION\n{name} IN {rdtype}\n;ANSWER\n"
        + "\n".join(lines)
        + "\n;AUTHORITY\n;ADDITIONAL\n"
    )


@pytest.mark.parametrize("rdtype", ["a", " MX ", "txt", "SOA"])
def test_check_type_accepts_supported(rdtype):
    assert check_type(rdtype) == rdtype.strip().upper()


def test_check_type_rejects_unknown():
    with pytest.raises(ValueError, match="unsupported record type"):
        check_type("SRVX")


@pytest.mark.parametrize(
    ("rdtype", "raw", "expected"),
    [
        ("A", " 192.0.2.10 ", "192.0.2.10"),
        ("AAAA", "2001:DB8:0:0::1", "2001:db8::1"),
        ("CNAME", "Target.Example.NET", "target.example.net."),
        ("NS", "ns1.example.com.", "ns1.example.com."),
        ("MX", "10 Mail.Example.com", "10 mail.example.com."),
        ("MX", "mail.example.com", "* mail.example.com."),
        ("TXT", '"v=spf1 -all"', "v=spf1 -all"),
        ("TXT", "google-site-verification=abc", "google-site-verification=abc"),
        ("CAA", '0 issue "letsencrypt.org"', "0 issue letsencrypt.org"),
        ("CAA", "issuewild sectigo.com", "0 issuewild sectigo.com"),
        ("SOA", "2026111901", "2026111901"),
        ("SOA", "NS1.example.com. hostmaster.example.com. 7 3600 600 86400 300", None),
    ],
)
def test_normalize_expected(rdtype, raw, expected):
    if expected is None:
        assert normalize_expected(rdtype, raw) == "ns1.example.com. hostmaster.example.com. 7 3600 600 86400 300"
    else:
        assert normalize_expected(rdtype, raw) == expected


@pytest.mark.parametrize(
    ("rdtype", "raw"),
    [
        ("A", "2001:db8::1"),
        ("AAAA", "192.0.2.1"),
        ("A", "not-an-ip"),
        ("MX", "ten mail.example.com"),
        ("CAA", "issue"),
        ("SOA", "ns1 hostmaster 1 2"),
        ("TXT", "   "),
    ],
)
def test_normalize_expected_rejects_invalid(rdtype, raw):
    with pytest.raises(ValueError):
        normalize_expected(rdtype, raw)


def test_exact_and_contains_matching():
    answers = ("192.0.2.1", "192.0.2.2")
    assert answers_match("A", answers, ["192.0.2.2", "192.0.2.1"])
    assert not answers_match("A", answers, ["192.0.2.1"])
    assert answers_match("A", answers, ["192.0.2.1"], "contains")
    assert not answers_match("A", answers, ["192.0.2.9"], "contains")
    assert not answers_match("A", (), ["192.0.2.1"], "contains")


def test_mx_without_preference_and_soa_serial():
    assert answers_match("MX", ("10 mx1.example.com.", "20 mx1.example.com."), ["* mx1.example.com."])
    soa = ("ns1.example.com. hostmaster.example.com. 2026111901 3600 600 86400 300",)
    assert answers_match("SOA", soa, ["2026111901"])
    assert not answers_match("SOA", soa, ["2026111900"])


def test_parse_response_a_with_cname_chain():
    msg = response(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RD RA\n;QUESTION\nwww.example.com. IN A\n;ANSWER\n"
        "www.example.com. 600 IN CNAME edge.example.net.\n"
        "edge.example.net. 60 IN A 192.0.2.7\n"
        "edge.example.net. 60 IN A 192.0.2.5\n;AUTHORITY\n;ADDITIONAL\n"
    )
    result = parse_response(msg, "A", 4.2)
    assert result.status == "ok"
    assert result.answers == ("192.0.2.5", "192.0.2.7")
    assert result.ttl == 60
    assert result.elapsed_ms == 4.2


def test_parse_response_record_types():
    assert parse_response(answer("MX", "10 MX.Example.com."), "MX").answers == ("10 mx.example.com.",)
    txt = parse_response(answer("TXT", '"v=spf1 include:_spf.example.net " "-all"'), "TXT")
    assert txt.answers == ("v=spf1 include:_spf.example.net -all",)
    caa = parse_response(answer("CAA", '0 issue "letsencrypt.org"'), "CAA")
    assert caa.answers == ("0 issue letsencrypt.org",)
    soa = parse_response(answer("SOA", "ns1.example.com. hostmaster.example.com. 5 7200 900 1209600 300"), "SOA")
    assert soa.answers == ("ns1.example.com. hostmaster.example.com. 5 7200 900 1209600 300",)
    aaaa = parse_response(answer("AAAA", "2001:db8:0::1"), "AAAA")
    assert aaaa.answers == ("2001:db8::1",)


def test_parse_response_statuses():
    assert parse_response(answer("A", rcode="NXDOMAIN"), "A").status == "nxdomain"
    assert parse_response(answer("A", rcode="SERVFAIL"), "A").status == "servfail"
    assert parse_response(answer("A", rcode="REFUSED"), "A").status == "refused"
    assert parse_response(answer("A"), "A").status == "noanswer"
    formerr = parse_response(answer("A", rcode="FORMERR"), "A")
    assert formerr.status == "error"
    assert formerr.responded is False
