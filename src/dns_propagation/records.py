"""Record types, normalisation of answers and expected values, and matching."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from typing import Any

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "CAA", "SOA")
MATCH_MODES = ("exact", "contains")


def check_type(rdtype: str) -> str:
    value = rdtype.strip().upper()
    if value not in RECORD_TYPES:
        raise ValueError(f"unsupported record type {rdtype!r}; choose from {', '.join(RECORD_TYPES)}")
    return value


def _fqdn(name: str) -> str:
    name = name.strip().lower()
    if not name:
        raise ValueError("empty host name")
    return name if name.endswith(".") else name + "."


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def normalize_rdata(rdtype: str, rdata: Any) -> str:
    """Turn a dnspython rdata object into the canonical text used for comparison."""
    if rdtype in ("A", "AAAA"):
        return str(ipaddress.ip_address(rdata.address))
    if rdtype in ("CNAME", "NS"):
        return rdata.target.to_text().lower()
    if rdtype == "MX":
        return f"{rdata.preference} {rdata.exchange.to_text().lower()}"
    if rdtype == "TXT":
        return b"".join(rdata.strings).decode("utf-8", "replace")
    if rdtype == "CAA":
        return f"{rdata.flags} {rdata.tag.decode('ascii', 'replace').lower()} {rdata.value.decode('utf-8', 'replace')}"
    if rdtype == "SOA":
        return (
            f"{rdata.mname.to_text().lower()} {rdata.rname.to_text().lower()} "
            f"{rdata.serial} {rdata.refresh} {rdata.retry} {rdata.expire} {rdata.minimum}"
        )
    return str(rdata.to_text())


def normalize_expected(rdtype: str, value: str) -> str:
    """Normalise a user supplied expected value. Raises ``ValueError`` when invalid."""
    value = value.strip()
    if not value:
        raise ValueError("empty expected value")
    if rdtype == "A":
        ip = ipaddress.ip_address(value)
        if ip.version != 4:
            raise ValueError(f"{value!r} is not an IPv4 address")
        return str(ip)
    if rdtype == "AAAA":
        ip = ipaddress.ip_address(value)
        if ip.version != 6:
            raise ValueError(f"{value!r} is not an IPv6 address")
        return str(ip)
    if rdtype in ("CNAME", "NS"):
        return _fqdn(value)
    if rdtype == "MX":
        parts = value.split()
        if len(parts) == 1:
            return f"* {_fqdn(parts[0])}"
        if len(parts) != 2 or not parts[0].isdigit():
            raise ValueError(f"MX value must be 'PREFERENCE HOST' or 'HOST': {value!r}")
        return f"{int(parts[0])} {_fqdn(parts[1])}"
    if rdtype == "TXT":
        return _unquote(value)
    if rdtype == "CAA":
        parts = value.split(None, 2)
        if len(parts) == 2:
            parts = ["0", *parts]
        if len(parts) != 3 or not parts[0].isdigit():
            raise ValueError(f"CAA value must be 'FLAGS TAG VALUE', for example '0 issue letsencrypt.org': {value!r}")
        return f"{int(parts[0])} {parts[1].lower()} {_unquote(parts[2])}"
    if rdtype == "SOA":
        if value.isdigit():
            return value
        parts = value.split()
        if len(parts) != 7 or not all(p.isdigit() for p in parts[2:]):
            raise ValueError("SOA value must be a serial number or 'MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM'")
        return " ".join([_fqdn(parts[0]), _fqdn(parts[1]), *(str(int(p)) for p in parts[2:])])
    return value


def value_matches(rdtype: str, answer: str, expected: str) -> bool:
    """Whether one normalised answer matches one normalised expected value."""
    if rdtype == "MX" and expected.startswith("* "):
        return answer.split(" ", 1)[-1] == expected[2:]
    if rdtype == "SOA" and expected.isdigit():
        parts = answer.split()
        return len(parts) == 7 and parts[2] == expected
    return answer == expected


def answers_match(rdtype: str, answers: Sequence[str], expected: Iterable[str], mode: str = "exact") -> bool:
    """Compare a resolver's answers with the expected values.

    ``exact``: every answer matches an expected value and every expected value is present.
    ``contains``: every expected value is present; extra answers are allowed.
    """
    expected = list(expected)
    if not answers:
        return False
    every_expected_seen = all(any(value_matches(rdtype, a, e) for a in answers) for e in expected)
    if mode == "contains":
        return every_expected_seen
    return every_expected_seen and all(any(value_matches(rdtype, a, e) for e in expected) for a in answers)
