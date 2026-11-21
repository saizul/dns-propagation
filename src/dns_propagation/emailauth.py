"""SPF, DMARC, DKIM, MTA-STS and TLS-RPT record presence and syntax checks."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from .query import QueryResult

Lookup = Callable[[str, str], QueryResult]
"""``lookup(name, rdtype)`` returns a :class:`QueryResult`."""

LEVELS = ("ok", "info", "warning", "error")

EMAIL_CHECKS = ("mx", "spf", "dmarc", "dkim", "mta-sts", "tls-rpt")
"""Every check ``check_domain`` knows, in report order."""

COMMON_DKIM_SELECTORS = (
    "default",
    "dkim",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "s1",
    "s2",
    "mail",
    "smtp",
    "mxvm",
    "zoho",
    "protonmail",
    "mandrill",
    "pm",
    "sig1",
    "fm1",
)

SPF_MECHANISMS = ("all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists")
SPF_LOOKUP_TERMS = ("include", "a", "mx", "ptr", "exists", "redirect")
SPF_MAX_LOOKUPS = 10
SPF_MAX_VOID = 2

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_%{}.-]+)$")


@dataclass(frozen=True)
class Finding:
    check: str
    level: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"check": self.check, "level": self.level, "message": self.message}


@dataclass
class EmailReport:
    domain: str
    records: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    lookup_failures: int = 0
    lookups: int = 0

    def add(self, check: str, level: str, message: str) -> None:
        self.findings.append(Finding(check, level, message))

    @property
    def errors(self) -> int:
        return sum(1 for f in self.findings if f.level == "error")

    @property
    def warnings(self) -> int:
        return sum(1 for f in self.findings if f.level == "warning")

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "records": self.records,
            "findings": [f.to_dict() for f in self.findings],
            "summary": {"errors": self.errors, "warnings": self.warnings, "passed": self.errors == 0},
        }


# --------------------------------------------------------------------------- SPF


@dataclass
class SpfTerm:
    qualifier: str
    name: str
    value: str
    modifier: bool = False

    def __str__(self) -> str:
        if self.modifier:
            return f"{self.name}={self.value}"
        sep = ":" if self.value and not self.value.startswith("/") else ""
        return f"{'' if self.qualifier == '+' else self.qualifier}{self.name}{sep}{self.value}"


@dataclass
class SpfRecord:
    terms: list[SpfTerm] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def lookup_terms(self) -> list[SpfTerm]:
        return [t for t in self.terms if t.name in SPF_LOOKUP_TERMS]

    def modifier(self, name: str) -> str | None:
        for term in self.terms:
            if term.modifier and term.name == name:
                return term.value
        return None


def is_spf(text: str) -> bool:
    return text.lower() == "v=spf1" or text.lower().startswith("v=spf1 ")


def _valid_domain_spec(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value)) and ".." not in value


def _check_cidr(value: str, maximum: int) -> bool:
    return value.isdigit() and 0 <= int(value) <= maximum


def parse_spf(text: str) -> SpfRecord:
    """Parse an SPF record (RFC 7208) and collect syntax errors and warnings."""
    record = SpfRecord()
    tokens = text.split()
    if not tokens or tokens[0].lower() != "v=spf1":
        record.errors.append("record must start with 'v=spf1'")
        return record
    seen_all = False
    for token in tokens[1:]:
        if seen_all:
            record.warnings.append(f"'{token}' after 'all' is ignored")
            continue
        match = re.match(r"^([A-Za-z][A-Za-z0-9_.-]*)=(.*)$", token)
        if match:
            name, value = match.group(1).lower(), match.group(2)
            if name in ("redirect", "exp"):
                if record.modifier(name) is not None:
                    record.errors.append(f"'{name}' modifier appears more than once")
                if not _valid_domain_spec(value):
                    record.errors.append(f"'{name}' needs a domain: {token!r}")
            record.terms.append(SpfTerm("", name, value, modifier=True))
            continue
        qualifier = "+"
        if token[0] in "+-~?":
            qualifier, token = token[0], token[1:]
        name, _, value = token.partition(":")
        cidr = ""
        if "/" in (value or name):
            if value:
                value, _, cidr = value.partition("/")
            else:
                name, _, cidr = name.partition("/")
        name = name.lower()
        if name not in SPF_MECHANISMS:
            record.errors.append(f"unknown mechanism {token!r}")
            continue
        term_value = value + (f"/{cidr}" if cidr else "")
        if name == "all":
            if value or cidr:
                record.errors.append("'all' takes no arguments")
            seen_all = True
        elif name in ("include", "exists"):
            if not value or not _valid_domain_spec(value) or cidr:
                record.errors.append(f"'{name}' needs a domain: {token!r}")
        elif name == "ip4":
            try:
                ipaddress.IPv4Network(term_value, strict=False)
            except ValueError:
                record.errors.append(f"invalid IPv4 address or range: {token!r}")
        elif name == "ip6":
            try:
                ipaddress.IPv6Network(term_value, strict=False)
            except ValueError:
                record.errors.append(f"invalid IPv6 address or range: {token!r}")
        elif name in ("a", "mx"):
            if value and not _valid_domain_spec(value):
                record.errors.append(f"invalid domain in {token!r}")
            if cidr:
                v4, _, v6 = cidr.partition("//")
                if (v4 and not _check_cidr(v4, 32)) or (v6 and not _check_cidr(v6, 128)):
                    record.errors.append(f"invalid prefix length in {token!r}")
        elif name == "ptr":
            record.warnings.append("'ptr' is deprecated (RFC 7208 section 5.5) and slow; list the addresses instead")
        record.terms.append(SpfTerm(qualifier, name, term_value))
    all_terms = [t for t in record.terms if t.name == "all" and not t.modifier]
    if all_terms and record.modifier("redirect") is not None:
        record.warnings.append("'redirect' is ignored because the record has an 'all' mechanism")
    if not all_terms and record.modifier("redirect") is None:
        record.warnings.append("no 'all' mechanism or 'redirect': unlisted senders get a neutral result")
    for term in all_terms:
        if term.qualifier == "+":
            record.errors.append("'+all' allows every server on the internet to send as this domain")
        elif term.qualifier == "?":
            record.warnings.append("'?all' (neutral) gives no protection; use '~all' or '-all'")
    return record


def _txt(lookup: Lookup, name: str, report: EmailReport) -> list[str] | None:
    report.lookups += 1
    result = lookup(name, "TXT")
    if result.status == "ok":
        return list(result.answers)
    if result.status in ("nxdomain", "noanswer"):
        return []
    report.lookup_failures += 1
    return None


def _spf_lookups(
    lookup: Lookup, record: SpfRecord, domain: str, seen: set[str], depth: int, report: EmailReport
) -> tuple[int, int, list[str]]:
    """Count DNS-querying terms recursively. Returns ``(lookups, void_lookups, problems)``."""
    count, void, problems = 0, 0, []
    targets: list[str] = []
    has_all = any(t.name == "all" and not t.modifier for t in record.terms)
    for term in record.lookup_terms:
        if term.name == "redirect" and has_all:
            continue
        count += 1
        if term.name in ("include", "redirect"):
            targets.append(term.value)
    for target in targets:
        target_l = target.lower().rstrip(".")
        if "%" in target_l:
            continue  # macros are expanded at evaluation time
        if target_l in seen:
            problems.append(f"include loop through {target_l}")
            continue
        if depth >= SPF_MAX_LOOKUPS:
            problems.append("includes nested too deeply")
            break
        texts = _txt(lookup, target_l, report)
        if texts is None:
            problems.append(f"could not look up {target_l}")
            continue
        spf = [t for t in texts if is_spf(t)]
        if not spf:
            void += 1
            problems.append(f"{target_l} has no SPF record (include fails with permerror)")
            continue
        sub_count, sub_void, sub_problems = _spf_lookups(
            lookup, parse_spf(spf[0]), target_l, seen | {target_l}, depth + 1, report
        )
        count += sub_count
        void += sub_void
        problems.extend(sub_problems)
    return count, void, problems


def check_spf(lookup: Lookup, domain: str, report: EmailReport, recursive: bool = True) -> None:
    texts = _txt(lookup, domain, report)
    if texts is None:
        report.add("spf", "error", f"TXT lookup for {domain} failed")
        return
    spf = [t for t in texts if is_spf(t)]
    report.records["spf"] = spf
    if not spf:
        report.add("spf", "error", "no SPF record (TXT starting with 'v=spf1')")
        return
    if len(spf) > 1:
        report.add("spf", "error", f"{len(spf)} SPF records found; there must be exactly one (permerror)")
    record = parse_spf(spf[0])
    for message in record.errors:
        report.add("spf", "error", message)
    for message in record.warnings:
        report.add("spf", "warning", message)
    if len(spf[0]) > 450:
        report.add(
            "spf", "warning", f"record is {len(spf[0])} characters; long records may be truncated by some servers"
        )
    if record.errors:
        return
    if recursive:
        count, void, problems = _spf_lookups(lookup, record, domain, {domain}, 0, report)
        for problem in problems:
            report.add("spf", "error" if "permerror" in problem or "loop" in problem else "warning", problem)
        report.records["spf_lookups"] = count
        if count > SPF_MAX_LOOKUPS:
            report.add("spf", "error", f"{count} DNS lookups needed; the limit is {SPF_MAX_LOOKUPS} (permerror)")
        elif count >= SPF_MAX_LOOKUPS - 2:
            report.add("spf", "warning", f"{count} of {SPF_MAX_LOOKUPS} DNS lookups used")
        if void > SPF_MAX_VOID:
            report.add("spf", "error", f"{void} void lookups; the limit is {SPF_MAX_VOID}")
    else:
        count = len(record.lookup_terms)
        report.records["spf_lookups"] = count
        if count > SPF_MAX_LOOKUPS:
            report.add("spf", "error", f"{count} DNS lookups in the top-level record; the limit is {SPF_MAX_LOOKUPS}")
    if not report_has(report, "spf", "error"):
        report.add("spf", "ok", "SPF record is valid")


def report_has(report: EmailReport, check: str, level: str) -> bool:
    return any(f.check == check and f.level == level for f in report.findings)


# --------------------------------------------------------------------------- DMARC


def parse_tags(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Parse ``tag=value; tag=value`` lists (DMARC and DKIM)."""
    tags: list[tuple[str, str]] = []
    problems: list[str] = []
    for part in text.split(";"):
        part = part.strip()
        if not part:
            continue
        name, sep, value = part.partition("=")
        if not sep:
            problems.append(f"'{part}' is not a tag=value pair")
            continue
        tags.append((name.strip().lower(), value.strip()))
    return tags, problems


DMARC_TAGS = ("v", "p", "sp", "np", "rua", "ruf", "pct", "adkim", "aspf", "fo", "rf", "ri", "t", "psd")
DMARC_POLICIES = ("none", "quarantine", "reject")


def validate_dmarc(text: str) -> tuple[dict[str, str], list[str], list[str]]:
    """Validate a DMARC record (RFC 7489). Returns ``(tags, errors, warnings)``."""
    errors: list[str] = []
    warnings: list[str] = []
    pairs, problems = parse_tags(text)
    errors.extend(problems)
    tags: dict[str, str] = {}
    for name, value in pairs:
        if name in tags:
            errors.append(f"tag '{name}' appears more than once")
        tags.setdefault(name, value)
    if not pairs or pairs[0][0] != "v" or pairs[0][1] != "DMARC1":
        errors.append("record must start with 'v=DMARC1'")
    if "p" not in tags:
        errors.append("required tag 'p' (policy) is missing")
    for key in ("p", "sp", "np"):
        if key in tags and tags[key].lower() not in DMARC_POLICIES:
            errors.append(f"{key}={tags[key]} is not one of none, quarantine, reject")
    if tags.get("p", "").lower() == "none":
        warnings.append("p=none only monitors; move to quarantine or reject once reports look clean")
    if "pct" in tags:
        if not tags["pct"].isdigit() or not 0 <= int(tags["pct"]) <= 100:
            errors.append(f"pct={tags['pct']} must be a number from 0 to 100")
        elif int(tags["pct"]) < 100:
            warnings.append(f"pct={tags['pct']}: the policy applies to only part of the failing mail")
    for key in ("adkim", "aspf"):
        if key in tags and tags[key].lower() not in ("r", "s"):
            errors.append(f"{key}={tags[key]} must be 'r' (relaxed) or 's' (strict)")
    for key in ("rua", "ruf"):
        if key in tags:
            for uri in (u.strip() for u in tags[key].split(",")):
                address = uri.split("!", 1)[0]
                if not address.lower().startswith("mailto:") or "@" not in address:
                    errors.append(f"{key} entry {uri!r} must be a mailto: address")
    if "rua" not in tags:
        warnings.append("no 'rua' tag: you will not receive aggregate reports")
    if "fo" in tags:
        for option in tags["fo"].split(":"):
            if option.strip() not in ("0", "1", "d", "s"):
                errors.append(f"fo option {option!r} must be 0, 1, d or s")
    if "ri" in tags and not tags["ri"].isdigit():
        errors.append(f"ri={tags['ri']} must be a number of seconds")
    if "rf" in tags and tags["rf"].lower() != "afrf":
        warnings.append(f"rf={tags['rf']}: only 'afrf' is defined")
    for name in tags:
        if name not in DMARC_TAGS:
            warnings.append(f"unknown tag '{name}' is ignored")
    return tags, errors, warnings


def check_dmarc(lookup: Lookup, domain: str, report: EmailReport) -> None:
    name = f"_dmarc.{domain}"
    texts = _txt(lookup, name, report)
    if texts is None:
        report.add("dmarc", "error", f"TXT lookup for {name} failed")
        return
    records = [t for t in texts if t.replace(" ", "").lower().startswith("v=dmarc1")]
    report.records["dmarc"] = records
    if not records:
        report.add("dmarc", "error", f"no DMARC record at {name}")
        return
    if len(records) > 1:
        report.add("dmarc", "error", f"{len(records)} DMARC records found; receivers ignore all of them")
    tags, errors, warnings = validate_dmarc(records[0])
    for message in errors:
        report.add("dmarc", "error", message)
    for message in warnings:
        report.add("dmarc", "warning", message)
    if not errors:
        report.add("dmarc", "ok", f"DMARC policy is p={tags.get('p', '').lower()}")


# --------------------------------------------------------------------------- DKIM


def _der_read(data: bytes, pos: int) -> tuple[int, bytes, int]:
    if pos + 2 > len(data):
        raise ValueError("truncated DER")
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        size = length & 0x7F
        if size == 0 or size > 4 or pos + size > len(data):
            raise ValueError("bad DER length")
        length = int.from_bytes(data[pos : pos + size], "big")
        pos += size
    if pos + length > len(data):
        raise ValueError("truncated DER")
    return tag, data[pos : pos + length], pos + length


def rsa_key_bits(der: bytes) -> int | None:
    """Modulus size of an RSA key in SubjectPublicKeyInfo or PKCS#1 form."""
    try:
        tag, body, _ = _der_read(der, 0)
        if tag != 0x30:
            return None
        first_tag, first, pos = _der_read(body, 0)
        if first_tag == 0x02:  # PKCS#1 RSAPublicKey: SEQUENCE { modulus, exponent }
            modulus = first
        elif first_tag == 0x30:  # SPKI: SEQUENCE { algorithm, BIT STRING { RSAPublicKey } }
            bit_tag, bits, _ = _der_read(body, pos)
            if bit_tag != 0x03 or not bits:
                return None
            seq_tag, rsa, _ = _der_read(bits[1:], 0)
            if seq_tag != 0x30:
                return None
            mod_tag, modulus, _ = _der_read(rsa, 0)
            if mod_tag != 0x02:
                return None
        else:
            return None
    except ValueError:
        return None
    return int.from_bytes(modulus, "big").bit_length()


def validate_dkim(text: str) -> tuple[dict[str, str], list[str], list[str], int | None]:
    """Validate a DKIM key record (RFC 6376). Returns ``(tags, errors, warnings, key_bits)``."""
    errors: list[str] = []
    warnings: list[str] = []
    pairs, problems = parse_tags(text)
    errors.extend(problems)
    tags: dict[str, str] = {}
    for name, value in pairs:
        if name in tags:
            errors.append(f"tag '{name}' appears more than once")
        tags.setdefault(name, value)
    if "v" in tags:
        if pairs[0][0] != "v":
            errors.append("'v' must be the first tag")
        if tags["v"] != "DKIM1":
            errors.append(f"v={tags['v']} must be DKIM1")
    key_type = tags.get("k", "rsa").lower()
    if key_type not in ("rsa", "ed25519"):
        errors.append(f"k={key_type} is not rsa or ed25519")
    if "p" not in tags:
        errors.append("required tag 'p' (public key) is missing")
        return tags, errors, warnings, None
    key_b64 = re.sub(r"\s+", "", tags["p"])
    if not key_b64:
        warnings.append("empty p= tag: this key has been revoked")
        return tags, errors, warnings, None
    try:
        key = base64.b64decode(key_b64, validate=True)
    except (binascii.Error, ValueError):
        errors.append("p= is not valid base64")
        return tags, errors, warnings, None
    bits: int | None = None
    if key_type == "rsa":
        bits = rsa_key_bits(key)
        if bits is None:
            errors.append("p= does not contain an RSA public key")
        elif bits < 1024:
            errors.append(f"RSA key is {bits} bits; receivers reject keys under 1024 bits")
        elif bits < 2048:
            warnings.append(f"RSA key is {bits} bits; 2048 bits is recommended")
    elif key_type == "ed25519":
        if len(key) != 32:
            errors.append(f"Ed25519 key must be 32 bytes, got {len(key)}")
        bits = 256
    if "h" in tags:
        hashes = {h.strip().lower() for h in tags["h"].split(":")}
        if hashes and hashes <= {"sha1"}:
            warnings.append("h=sha1 only: SHA-1 signatures are no longer accepted; allow sha256")
    if "y" in {f.strip().lower() for f in tags.get("t", "").split(":")}:
        warnings.append("t=y: the domain is testing DKIM and receivers may ignore failures")
    return tags, errors, warnings, bits


def check_dkim(lookup: Lookup, domain: str, selectors: Iterable[str], report: EmailReport) -> None:
    explicit = list(dict.fromkeys(s.strip() for s in selectors if s.strip()))
    probe = not explicit
    found: dict[str, dict[str, Any]] = {}
    for selector in explicit or COMMON_DKIM_SELECTORS:
        name = f"{selector}._domainkey.{domain}"
        texts = _txt(lookup, name, report)
        if texts is None:
            if not probe:
                report.add("dkim", "error", f"TXT lookup for {name} failed")
            continue
        keys = [t for t in texts if "p=" in t.replace(" ", "")]
        if not keys:
            if not probe:
                report.add("dkim", "error", f"no DKIM key at {name}")
            continue
        if len(keys) > 1:
            report.add("dkim", "warning", f"{selector}: {len(keys)} key records found; only one is used")
        tags, errors, warnings, bits = validate_dkim(keys[0])
        found[selector] = {"record": keys[0], "key_type": tags.get("k", "rsa").lower(), "key_bits": bits}
        for message in errors:
            report.add("dkim", "error", f"{selector}: {message}")
        for message in warnings:
            report.add("dkim", "warning", f"{selector}: {message}")
        if not errors and re.sub(r"\s+", "", tags.get("p", "")):
            detail = f", {bits}-bit {found[selector]['key_type']}" if bits else ""
            report.add("dkim", "ok", f"selector '{selector}' has a valid key{detail}")
    report.records["dkim"] = found
    if probe and not found:
        report.add(
            "dkim",
            "warning",
            "no DKIM key found under common selectors; pass --selector with the one your mail provider uses",
        )


# --------------------------------------------------------------------------- MX


# --------------------------------------------------------------------------- MTA-STS and TLS-RPT

_STS_ID_RE = re.compile(r"^[A-Za-z0-9]{1,32}$")


def _tag_record(texts: list[str], version: str) -> list[str]:
    """TXT strings that start with ``v=<version>`` (case-insensitive, spaces ignored)."""
    prefix = f"v={version}".lower()
    return [t for t in texts if t.replace(" ", "").lower().startswith(prefix)]


def validate_mta_sts(text: str) -> tuple[dict[str, str], list[str], list[str]]:
    """Validate an MTA-STS TXT record (RFC 8461 section 3.1). Returns ``(tags, errors, warnings)``."""
    errors: list[str] = []
    pairs, problems = parse_tags(text)
    errors.extend(problems)
    tags: dict[str, str] = {}
    for name, value in pairs:
        if name in tags:
            errors.append(f"tag '{name}' appears more than once")
        tags.setdefault(name, value)
    if not pairs or pairs[0] != ("v", "STSv1"):
        errors.append("record must start with 'v=STSv1'")
    if "id" not in tags:
        errors.append("required tag 'id' is missing; change it whenever the policy file changes")
    elif not _STS_ID_RE.match(tags["id"]):
        errors.append(f"id={tags['id']!r} must be 1 to 32 letters and digits")
    return tags, errors, []


def validate_tls_rpt(text: str) -> tuple[dict[str, str], list[str], list[str]]:
    """Validate an SMTP TLS reporting record (RFC 8460 section 3). Returns ``(tags, errors, warnings)``."""
    errors: list[str] = []
    pairs, problems = parse_tags(text)
    errors.extend(problems)
    tags: dict[str, str] = {}
    for name, value in pairs:
        if name in tags:
            errors.append(f"tag '{name}' appears more than once")
        tags.setdefault(name, value)
    if not pairs or pairs[0] != ("v", "TLSRPTv1"):
        errors.append("record must start with 'v=TLSRPTv1'")
    if "rua" not in tags:
        errors.append("required tag 'rua' (where reports are sent) is missing")
    else:
        for uri in (u.strip() for u in tags["rua"].split(",")):
            lower = uri.lower()
            if lower.startswith("mailto:"):
                if "@" not in uri:
                    errors.append(f"rua entry {uri!r} is not a mailto: address")
            elif not lower.startswith("https://") or len(uri) <= len("https://"):
                errors.append(f"rua entry {uri!r} must be a mailto: or https: URI")
    return tags, errors, []


def _check_policy_record(
    lookup: Lookup,
    report: EmailReport,
    check: str,
    name: str,
    version: str,
    validate: Callable[[str], tuple[dict[str, str], list[str], list[str]]],
    missing: str,
    ok: Callable[[dict[str, str]], str],
) -> bool:
    texts = _txt(lookup, name, report)
    if texts is None:
        report.add(check, "error", f"TXT lookup for {name} failed")
        return False
    records = _tag_record(texts, version)
    report.records[check] = records
    if not records:
        report.add(check, "info", missing)
        return False
    if len(records) > 1:
        report.add(check, "error", f"{len(records)} records found at {name}; senders ignore all of them")
    tags, errors, warnings = validate(records[0])
    for message in errors:
        report.add(check, "error", message)
    for message in warnings:
        report.add(check, "warning", message)
    if not errors and len(records) == 1:
        report.add(check, "ok", ok(tags))
    return True


def check_mta_sts(lookup: Lookup, domain: str, report: EmailReport) -> bool:
    """Check the ``_mta-sts`` TXT record. The HTTPS policy file itself is not fetched."""
    return _check_policy_record(
        lookup,
        report,
        "mta-sts",
        f"_mta-sts.{domain}",
        "STSv1",
        validate_mta_sts,
        f"no MTA-STS record at _mta-sts.{domain}: senders may deliver over unencrypted or unverified TLS",
        lambda tags: (
            f"MTA-STS record present (id={tags['id']}); serve the policy at "
            f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        ),
    )


def check_tls_rpt(lookup: Lookup, domain: str, report: EmailReport) -> bool:
    return _check_policy_record(
        lookup,
        report,
        "tls-rpt",
        f"_smtp._tls.{domain}",
        "TLSRPTv1",
        validate_tls_rpt,
        f"no TLS-RPT record at _smtp._tls.{domain}: you will not hear about TLS delivery failures",
        lambda tags: f"TLS reports go to {tags['rua']}",
    )


def check_mx(lookup: Lookup, domain: str, report: EmailReport) -> None:
    report.lookups += 1
    result = lookup(domain, "MX")
    if not result.responded:
        report.lookup_failures += 1
        report.add("mx", "error", f"MX lookup for {domain} failed: {result.error or result.status}")
        return
    report.records["mx"] = list(result.answers)
    if result.status == "nxdomain":
        report.add("mx", "error", f"{domain} does not exist (NXDOMAIN)")
    elif not result.answers:
        report.add("mx", "warning", "no MX records: this domain cannot receive mail (SPF/DMARC still matter)")
    elif result.answers == ("0 .",):
        report.add("mx", "info", "null MX (RFC 7505): the domain does not accept mail")
    else:
        report.add("mx", "ok", f"{len(result.answers)} MX record(s)")


def check_domain(
    lookup: Lookup,
    domain: str,
    selectors: Iterable[str] = (),
    *,
    checks: Iterable[str] = EMAIL_CHECKS,
    recursive_spf: bool = True,
) -> EmailReport:
    """Run the email authentication checks for ``domain`` (any of :data:`EMAIL_CHECKS`)."""
    domain = domain.strip().rstrip(".").lower()
    report = EmailReport(domain)
    wanted = set(checks)
    if "mx" in wanted:
        check_mx(lookup, domain, report)
    if "spf" in wanted:
        check_spf(lookup, domain, report, recursive=recursive_spf)
    if "dmarc" in wanted:
        check_dmarc(lookup, domain, report)
    if "dkim" in wanted:
        check_dkim(lookup, domain, selectors, report)
    has_sts = check_mta_sts(lookup, domain, report) if "mta-sts" in wanted else False
    has_rpt = check_tls_rpt(lookup, domain, report) if "tls-rpt" in wanted else False
    if has_sts and "tls-rpt" in wanted and not has_rpt:
        report.add("mta-sts", "warning", "MTA-STS without TLS-RPT: add a TLS-RPT record to learn about failures")
    return report
