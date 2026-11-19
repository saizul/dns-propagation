"""Built-in public resolvers, custom resolvers and selection."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

TRANSPORTS = ("udp", "tcp", "doh")


@dataclass(frozen=True)
class Resolver:
    """A recursive (or authoritative) DNS server."""

    id: str
    name: str
    provider: str
    region: str
    country: str = ""
    address: str = ""
    doh: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)

    def supports(self, transport: str) -> bool:
        return bool(self.doh) if transport == "doh" else bool(self.address)


@dataclass(frozen=True)
class Target:
    """One resolver reached over one transport."""

    resolver: Resolver
    transport: str = "udp"
    recursion: bool = True

    @property
    def endpoint(self) -> str:
        return self.resolver.doh if self.transport == "doh" else self.resolver.address

    @property
    def label(self) -> str:
        suffix = {"doh": " (DoH)", "tcp": " (TCP)"}.get(self.transport, "")
        return self.resolver.name + suffix


# Regions: "global" (anycast networks), "na", "eu", "asia".
BUILTIN: tuple[Resolver, ...] = (
    Resolver("cloudflare", "Cloudflare", "Cloudflare", "global", "", "1.1.1.1", "https://cloudflare-dns.com/dns-query"),
    Resolver("cloudflare-2", "Cloudflare secondary", "Cloudflare", "global", "", "1.0.0.1"),
    Resolver("google", "Google", "Google", "global", "", "8.8.8.8", "https://dns.google/dns-query"),
    Resolver("google-2", "Google secondary", "Google", "global", "", "8.8.4.4"),
    Resolver("quad9", "Quad9", "Quad9", "global", "CH", "9.9.9.9", "https://dns.quad9.net/dns-query", ("filtering",)),
    Resolver("quad9-2", "Quad9 secondary", "Quad9", "global", "CH", "149.112.112.112", "", ("filtering",)),
    Resolver("opendns", "OpenDNS", "Cisco", "global", "US", "208.67.222.222", "https://doh.opendns.com/dns-query"),
    Resolver("opendns-2", "OpenDNS secondary", "Cisco", "global", "US", "208.67.220.220"),
    Resolver(
        "adguard",
        "AdGuard",
        "AdGuard",
        "global",
        "CY",
        "94.140.14.14",
        "https://dns.adguard-dns.com/dns-query",
        ("filtering",),
    ),
    Resolver("controld", "Control D", "Control D", "global", "CA", "76.76.2.0", "https://freedns.controld.com/p0"),
    Resolver("cleanbrowsing", "CleanBrowsing", "CleanBrowsing", "global", "US", "185.228.168.9", "", ("filtering",)),
    Resolver("level3", "Lumen (Level 3)", "Lumen", "na", "US", "4.2.2.1"),
    Resolver("he", "Hurricane Electric", "Hurricane Electric", "na", "US", "74.82.42.42"),
    Resolver("comodo", "Comodo Secure DNS", "Comodo", "na", "US", "8.26.56.26", "", ("filtering",)),
    Resolver("ultradns", "UltraDNS Public", "Vercara", "na", "US", "64.6.64.6"),
    Resolver("dns4eu", "DNS4EU (unfiltered)", "DNS4EU", "eu", "EU", "86.54.11.100"),
    Resolver("mullvad", "Mullvad", "Mullvad", "eu", "SE", "", "https://dns.mullvad.net/dns-query"),
    Resolver("yandex", "Yandex", "Yandex", "eu", "RU", "77.88.8.8"),
    Resolver("alidns", "AliDNS", "Alibaba", "asia", "CN", "223.5.5.5", "https://dns.alidns.com/dns-query"),
    Resolver("dnspod", "DNSPod", "Tencent", "asia", "CN", "119.29.29.29"),
    Resolver("114dns", "114DNS", "114DNS", "asia", "CN", "114.114.114.114"),
    Resolver("quad101", "Quad101", "TWNIC", "asia", "TW", "101.101.101.101"),
    Resolver("kt", "KT", "KT", "asia", "KR", "168.126.63.1"),
    Resolver("iij", "IIJ Public DNS", "IIJ", "asia", "JP", "", "https://public.dns.iij.jp/dns-query"),
)

REGIONS = ("global", "na", "eu", "asia")


class ResolverError(ValueError):
    """Invalid resolver selection or definition."""


def by_id() -> dict[str, Resolver]:
    return {r.id: r for r in BUILTIN}


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def parse_custom(spec: str, index: int = 1) -> Resolver:
    """Parse ``ADDRESS``, ``NAME=ADDRESS`` or ``NAME=https://host/dns-query``."""
    spec = spec.strip()
    name, sep, address = spec.partition("=")
    if not sep:
        name, address = "", spec
    name, address = name.strip(), address.strip()
    if address.startswith("https://"):
        return Resolver(f"custom-{index}", name or address, "custom", "custom", doh=address)
    if not _is_ip(address):
        raise ResolverError(f"resolver address must be an IP address or an https:// DoH URL: {spec!r}")
    return Resolver(f"custom-{index}", name or address, "custom", "custom", address=address)


def load_file(path: str | Path) -> list[Resolver]:
    """Read resolvers from a text file: ``id address [region] [name ...]`` per line."""
    resolvers: list[Resolver] = []
    text = Path(path).read_text(encoding="utf-8")
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            raise ResolverError(f"{path}:{lineno}: expected 'id address [region] [name]'")
        rid, address = parts[0], parts[1]
        region = parts[2] if len(parts) > 2 else "custom"
        name = " ".join(parts[3:]) or rid
        if address.startswith("https://"):
            resolvers.append(Resolver(rid, name, "custom", region, doh=address))
        elif _is_ip(address):
            resolvers.append(Resolver(rid, name, "custom", region, address=address))
        else:
            raise ResolverError(f"{path}:{lineno}: {address!r} is not an IP address or https:// URL")
    if not resolvers:
        raise ResolverError(f"{path}: no resolvers found")
    return resolvers


def select(
    ids: Iterable[str] = (),
    regions: Iterable[str] = (),
    exclude_tags: Iterable[str] = (),
    pool: Iterable[Resolver] = BUILTIN,
) -> list[Resolver]:
    """Pick resolvers from ``pool`` by id or provider, region or country, minus tags."""
    pool = list(pool)
    wanted = [i.strip().lower() for i in ids if i.strip()]
    chosen = pool
    if wanted:
        chosen = []
        for want in wanted:
            matched = [r for r in pool if r.id == want] or [r for r in pool if r.provider.lower() == want]
            if not matched:
                raise ResolverError(f"unknown resolver {want!r} (see 'dns-propagation resolvers')")
            chosen.extend(r for r in matched if r not in chosen)
    region_set = {r.strip().lower() for r in regions if r.strip()}
    if region_set:
        chosen = [r for r in chosen if r.region.lower() in region_set or r.country.lower() in region_set]
    skip = {t.strip().lower() for t in exclude_tags if t.strip()}
    if skip:
        chosen = [r for r in chosen if not skip.intersection(r.tags)]
    return chosen


def targets_for(resolvers: Iterable[Resolver], transport: str = "udp") -> list[Target]:
    """Expand resolvers into targets. ``transport`` is ``udp``, ``tcp``, ``doh`` or ``all`` (udp and doh)."""
    if transport not in (*TRANSPORTS, "all"):
        raise ResolverError(f"unknown transport {transport!r}")
    wanted = ("udp", "doh") if transport == "all" else (transport,)
    return [Target(r, t) for r in resolvers for t in wanted if r.supports(t)]
