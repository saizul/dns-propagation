import ipaddress

import pytest

from dns_propagation.resolvers import (
    BUILTIN,
    REGIONS,
    ResolverError,
    by_id,
    load_file,
    parse_custom,
    select,
    targets_for,
)


def test_builtin_list_is_well_formed():
    ids = [r.id for r in BUILTIN]
    assert len(ids) == len(set(ids)) >= 20
    for r in BUILTIN:
        assert r.region in REGIONS
        assert r.address or r.doh
        if r.address:
            ipaddress.ip_address(r.address)
        if r.doh:
            assert r.doh.startswith("https://")
    for provider in ("Cloudflare", "Google", "Quad9", "Cisco", "AdGuard"):
        assert any(r.provider == provider for r in BUILTIN)
    assert {"eu", "asia", "na"} <= {r.region for r in BUILTIN}


def test_select_by_id_provider_region_and_tags():
    assert [r.id for r in select(["cloudflare", "google-2"])] == ["cloudflare", "google-2"]
    assert [r.id for r in select(["Google"])] == ["google"]
    assert {r.id for r in select(["cisco"])} == {"opendns", "opendns-2"}
    assert all(r.region == "asia" for r in select(regions=["asia"]))
    assert {r.id for r in select(regions=["cn"])} == {"alidns", "dnspod", "114dns"}
    assert not any("filtering" in r.tags for r in select(exclude_tags=["filtering"]))
    with pytest.raises(ResolverError, match="unknown resolver"):
        select(["nope"])


def test_select_does_not_duplicate():
    assert [r.id for r in select(["cloudflare", "cloudflare"])] == ["cloudflare"]


def test_parse_custom():
    plain = parse_custom("192.0.2.53")
    assert plain.address == "192.0.2.53" and plain.name == "192.0.2.53"
    named = parse_custom("office=10.0.0.1", 3)
    assert named.id == "custom-3" and named.name == "office" and named.address == "10.0.0.1"
    doh = parse_custom("nextdns=https://dns.nextdns.io/abc123")
    assert doh.doh == "https://dns.nextdns.io/abc123" and not doh.address
    with pytest.raises(ResolverError):
        parse_custom("resolver.example.com")


def test_targets_for_transports():
    pool = [by_id()["cloudflare"], by_id()["cloudflare-2"], by_id()["mullvad"]]
    assert [(t.resolver.id, t.transport) for t in targets_for(pool, "udp")] == [
        ("cloudflare", "udp"),
        ("cloudflare-2", "udp"),
    ]
    assert [t.resolver.id for t in targets_for(pool, "doh")] == ["cloudflare", "mullvad"]
    assert len(targets_for(pool, "all")) == 4
    assert [t.endpoint for t in targets_for(pool[:1], "tcp")] == ["1.1.1.1"]
    assert targets_for(pool[:1], "doh")[0].label == "Cloudflare (DoH)"
    with pytest.raises(ResolverError):
        targets_for(pool, "quic")


def test_load_file(tmp_path):
    path = tmp_path / "resolvers.txt"
    path.write_text(
        "# id address region name\n"
        "office 10.0.0.53 lan Office resolver\n"
        "isp 203.0.113.53   # trailing comment\n"
        "nextdns https://dns.nextdns.io/abc eu\n",
        encoding="utf-8",
    )
    resolvers = load_file(path)
    assert [r.id for r in resolvers] == ["office", "isp", "nextdns"]
    assert resolvers[0].name == "Office resolver" and resolvers[0].region == "lan"
    assert resolvers[1].region == "custom"
    assert resolvers[2].doh.startswith("https://")


@pytest.mark.parametrize("content", ["", "# only a comment\n", "lonely\n", "bad not-an-ip\n"])
def test_load_file_errors(tmp_path, content):
    path = tmp_path / "r.txt"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ResolverError):
        load_file(path)
