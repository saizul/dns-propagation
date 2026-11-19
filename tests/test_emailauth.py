import base64

import pytest

from conftest import NX, TIMEOUT, ok
from dns_propagation.emailauth import (
    check_domain,
    parse_spf,
    rsa_key_bits,
    validate_dkim,
    validate_dmarc,
)

# --------------------------------------------------------------------------- DER helpers


def der(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + body


def der_int(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 8) // 8, "big")  # leading zero keeps it positive
    return der(0x02, raw)


def rsa_spki(bits: int) -> bytes:
    modulus = (1 << (bits - 1)) | 1
    rsa = der(0x30, der_int(modulus) + der_int(65537))
    algorithm = der(0x30, der(0x06, bytes.fromhex("2a864886f70d010101")) + der(0x05, b""))
    return der(0x30, algorithm + der(0x03, b"\x00" + rsa))


def dkim_record(bits: int = 2048, extra: str = "") -> str:
    return f"v=DKIM1; k=rsa;{extra} p={base64.b64encode(rsa_spki(bits)).decode()}"


# --------------------------------------------------------------------------- SPF


def test_parse_valid_spf():
    record = parse_spf(
        "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx:mail.example.com/24 include:_spf.example.net -all"
    )
    assert record.errors == [] and record.warnings == []
    assert [t.name for t in record.lookup_terms] == ["a", "mx", "include"]


@pytest.mark.parametrize(
    ("record", "message"),
    [
        ("spf1 -all", "must start with 'v=spf1'"),
        ("v=spf1 ip4:192.0.2.300 -all", "invalid IPv4"),
        ("v=spf1 ip6:nope -all", "invalid IPv6"),
        ("v=spf1 include: -all", "needs a domain"),
        ("v=spf1 foo:bar -all", "unknown mechanism"),
        ("v=spf1 +all", "allows every server"),
        ("v=spf1 all:x", "takes no arguments"),
        ("v=spf1 a/40 -all", "invalid prefix length"),
        ("v=spf1 redirect=a.example redirect=b.example", "more than once"),
    ],
)
def test_parse_spf_errors(record, message):
    assert any(message in e for e in parse_spf(record).errors)


@pytest.mark.parametrize(
    ("record", "message"),
    [
        ("v=spf1 ptr -all", "deprecated"),
        ("v=spf1 ?all", "neutral"),
        ("v=spf1 ip4:192.0.2.1", "no 'all'"),
        ("v=spf1 -all ip4:192.0.2.1", "after 'all' is ignored"),
        ("v=spf1 redirect=_spf.example.net -all", "'redirect' is ignored"),
    ],
)
def test_parse_spf_warnings(record, message):
    assert any(message in w for w in parse_spf(record).warnings)


def lookup_from(table):
    def lookup(name, rdtype):
        return table.get((name, rdtype), NX)

    return lookup


def findings(report, check, level):
    return [f.message for f in report.findings if f.check == check and f.level == level]


def test_spf_recursive_lookup_count():
    table = {
        ("example.com", "TXT"): ok("v=spf1 include:a.example include:b.example mx -all", "other=text"),
        ("a.example", "TXT"): ok("v=spf1 include:c.example a ~all"),
        ("b.example", "TXT"): ok("v=spf1 ip4:192.0.2.0/24 -all"),
        ("c.example", "TXT"): ok("v=spf1 a mx exists:%{i}.x.example ~all"),
    }
    report = check_domain(lookup_from(table), "example.com", checks=["spf"])
    assert report.records["spf_lookups"] == 8
    assert findings(report, "spf", "warning") == ["8 of 10 DNS lookups used"]
    assert findings(report, "spf", "ok")


def test_spf_too_many_lookups_and_missing_include():
    many = " ".join(f"include:i{i}.example" for i in range(11))
    table = {("example.com", "TXT"): ok(f"v=spf1 {many} -all")}
    for i in range(11):
        table[(f"i{i}.example", "TXT")] = ok("v=spf1 -all")
    table[("i3.example", "TXT")] = ok("not spf")
    report = check_domain(lookup_from(table), "example.com", checks=["spf"])
    errors = findings(report, "spf", "error")
    assert any("11 DNS lookups" in e for e in errors)
    assert any("i3.example has no SPF record" in e for e in errors)
    assert not findings(report, "spf", "ok")


def test_spf_loop_multiple_and_missing():
    loop = {
        ("example.com", "TXT"): ok("v=spf1 include:a.example -all"),
        ("a.example", "TXT"): ok("v=spf1 include:example.com -all"),
    }
    assert any(
        "loop" in e for e in findings(check_domain(lookup_from(loop), "example.com", checks=["spf"]), "spf", "error")
    )

    two = {("example.com", "TXT"): ok("v=spf1 -all", "v=spf1 mx -all")}
    assert any(
        "2 SPF records" in e
        for e in findings(check_domain(lookup_from(two), "example.com", checks=["spf"]), "spf", "error")
    )

    none = check_domain(lookup_from({}), "example.com", checks=["spf"])
    assert findings(none, "spf", "error") == ["no SPF record (TXT starting with 'v=spf1')"]


def test_spf_non_recursive():
    table = {("example.com", "TXT"): ok("v=spf1 include:a.example include:b.example -all")}
    report = check_domain(lookup_from(table), "example.com", checks=["spf"], recursive_spf=False)
    assert report.records["spf_lookups"] == 2
    assert report.lookups == 1


# --------------------------------------------------------------------------- DMARC


def test_valid_dmarc():
    tags, errors, warnings = validate_dmarc(
        "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; adkim=s; pct=100; fo=1:d"
    )
    assert errors == [] and warnings == []
    assert tags["p"] == "reject"


@pytest.mark.parametrize(
    ("record", "message"),
    [
        ("p=reject; v=DMARC1", "must start with 'v=DMARC1'"),
        ("v=DMARC1; rua=mailto:a@example.com", "'p' (policy) is missing"),
        ("v=DMARC1; p=block", "not one of none"),
        ("v=DMARC1; p=reject; pct=150", "0 to 100"),
        ("v=DMARC1; p=reject; adkim=x", "relaxed"),
        ("v=DMARC1; p=reject; rua=https://example.com/report", "mailto"),
        ("v=DMARC1; p=reject; p=none", "more than once"),
        ("v=DMARC1; p=reject; fo=2", "fo option"),
        ("v=DMARC1; p=reject; junk", "tag=value"),
    ],
)
def test_dmarc_errors(record, message):
    _, errors, _ = validate_dmarc(record)
    assert any(message in e for e in errors), errors


def test_dmarc_warnings():
    _, errors, warnings = validate_dmarc("v=DMARC1; p=none; pct=50; foo=bar")
    assert errors == []
    joined = " | ".join(warnings)
    for fragment in ("p=none only monitors", "pct=50", "no 'rua'", "unknown tag 'foo'"):
        assert fragment in joined


def test_check_dmarc_lookup():
    table = {("_dmarc.example.com", "TXT"): ok("v=DMARC1; p=quarantine; rua=mailto:d@example.com")}
    report = check_domain(lookup_from(table), "example.com", checks=["dmarc"])
    assert findings(report, "dmarc", "ok") == ["DMARC policy is p=quarantine"]
    missing = check_domain(lookup_from({}), "example.com", checks=["dmarc"])
    assert findings(missing, "dmarc", "error") == ["no DMARC record at _dmarc.example.com"]


# --------------------------------------------------------------------------- DKIM


@pytest.mark.parametrize("bits", [1024, 2048, 4096])
def test_rsa_key_bits(bits):
    assert rsa_key_bits(rsa_spki(bits)) == bits


def test_rsa_key_bits_pkcs1_and_garbage():
    pkcs1 = der(0x30, der_int((1 << 2047) | 1) + der_int(65537))
    assert rsa_key_bits(pkcs1) == 2048
    assert rsa_key_bits(b"\x30\x05abc") is None
    assert rsa_key_bits(b"hello world") is None


def test_validate_dkim():
    _, errors, warnings, bits = validate_dkim(dkim_record(2048))
    assert (errors, warnings, bits) == ([], [], 2048)
    _, errors, warnings, bits = validate_dkim(dkim_record(1024, " h=sha1; t=y;"))
    assert errors == [] and bits == 1024
    assert any("2048 bits is recommended" in w for w in warnings)
    assert any("SHA-1" in w for w in warnings)
    assert any("testing" in w for w in warnings)
    _, errors, _, _ = validate_dkim(dkim_record(512))
    assert any("under 1024" in e for e in errors)


@pytest.mark.parametrize(
    ("record", "message"),
    [
        ("v=DKIM1; k=rsa", "'p' (public key) is missing"),
        ("v=DKIM1; p=***", "not valid base64"),
        ("k=rsa; v=DKIM1; p=", "first tag"),
        ("v=DKIM2; p=", "must be DKIM1"),
        ("v=DKIM1; k=dsa; p=", "not rsa or ed25519"),
        (f"v=DKIM1; p={base64.b64encode(b'not a key').decode()}", "does not contain an RSA"),
        (f"v=DKIM1; k=ed25519; p={base64.b64encode(b'x' * 16).decode()}", "32 bytes"),
    ],
)
def test_dkim_errors(record, message):
    _, errors, _, _ = validate_dkim(record)
    assert any(message in e for e in errors), errors


def test_dkim_ed25519_and_revoked():
    _, errors, _, bits = validate_dkim(f"v=DKIM1; k=ed25519; p={base64.b64encode(b'k' * 32).decode()}")
    assert errors == [] and bits == 256
    _, errors, warnings, _ = validate_dkim("v=DKIM1; p=")
    assert errors == [] and "revoked" in warnings[0]


def test_check_dkim_selectors_and_probe():
    table = {("s1._domainkey.example.com", "TXT"): ok(dkim_record(2048))}
    report = check_domain(lookup_from(table), "example.com", ["s1", "missing"], checks=["dkim"])
    assert findings(report, "dkim", "ok") == ["selector 's1' has a valid key, 2048-bit rsa"]
    assert findings(report, "dkim", "error") == ["no DKIM key at missing._domainkey.example.com"]

    probe = {("google._domainkey.example.com", "TXT"): ok(dkim_record(2048))}
    report = check_domain(lookup_from(probe), "example.com", checks=["dkim"])
    assert list(report.records["dkim"]) == ["google"]
    assert report.errors == 0

    nothing = check_domain(lookup_from({}), "example.com", checks=["dkim"])
    assert "no DKIM key found under common selectors" in findings(nothing, "dkim", "warning")[0]


def test_revoked_selector_is_not_reported_valid():
    table = {("old._domainkey.example.com", "TXT"): ok("v=DKIM1; p=")}
    report = check_domain(lookup_from(table), "example.com", ["old"], checks=["dkim"])
    assert findings(report, "dkim", "ok") == []
    assert "revoked" in findings(report, "dkim", "warning")[0]


# --------------------------------------------------------------------------- MX and full run


def test_mx_variants():
    assert findings(check_domain(lookup_from({}), "example.com", checks=["mx"]), "mx", "error")
    null = {("example.com", "MX"): ok("0 .")}
    assert findings(check_domain(lookup_from(null), "example.com", checks=["mx"]), "mx", "info")
    timeout = check_domain(lambda n, t: TIMEOUT, "example.com", checks=["mx"])
    assert timeout.lookup_failures == 1


def test_full_report_passes():
    table = {
        ("example.com", "MX"): ok("10 mx.example.com."),
        ("example.com", "TXT"): ok("v=spf1 mx -all"),
        ("_dmarc.example.com", "TXT"): ok("v=DMARC1; p=reject; rua=mailto:d@example.com"),
        ("mail._domainkey.example.com", "TXT"): ok(dkim_record()),
    }
    report = check_domain(lookup_from(table), "Example.com.", ["mail"])
    data = report.to_dict()
    assert data["domain"] == "example.com"
    assert data["summary"] == {"errors": 0, "warnings": 0, "passed": True}
    assert {f["check"] for f in data["findings"]} == {"mx", "spf", "dmarc", "dkim"}
