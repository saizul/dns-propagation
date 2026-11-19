# dns-propagation

[![CI](https://github.com/saizul/dns-propagation/actions/workflows/ci.yml/badge.svg)](https://github.com/saizul/dns-propagation/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/saizul/dns-propagation?sort=semver)](https://github.com/saizul/dns-propagation/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Container image](https://img.shields.io/badge/ghcr.io-saizul%2Fdns--propagation-2496ED?logo=docker&logoColor=white)](https://github.com/saizul/dns-propagation/pkgs/container/dns-propagation)
![Python](https://img.shields.io/badge/python-3.11%E2%80%933.13-blue)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**"Has my DNS change propagated yet?", answered from your terminal or your CI pipeline.**
dns-propagation asks 20+ public resolvers (Cloudflare, Google, Quad9, OpenDNS, AdGuard,
Control D, regional resolvers in Europe and Asia) at the same time, over plain DNS or
DNS over HTTPS, and shows who already sees the new value. It can compare against an
expected value or against the zone's own authoritative servers, wait until a change is
everywhere, and check that SPF, DMARC and DKIM records are present and valid.

```text
$ dns-propagation example.com A --expect 203.0.113.10
example.com A
expected: 203.0.113.10

RESOLVER    REGION  ADDRESS         STATUS    TTL   TIME     ANSWER
Cloudflare  global  1.1.1.1         match     300   12 ms    203.0.113.10
Google      global  8.8.8.8         MISMATCH  1740  12 ms    198.51.100.7
Quad9       global  9.9.9.9         match     300   12 ms    203.0.113.10
AdGuard     global  94.140.14.14    TIMEOUT         3000 ms  no answer within 3s
OpenDNS     global  208.67.222.222  match     300   12 ms    203.0.113.10
AliDNS      CN      223.5.5.5       match     300   12 ms    203.0.113.10

Propagation: 66.7% (4/6 resolvers match, threshold 100%)
Consistency: 80% of 5 responding resolvers agree on: 203.0.113.10
1 resolver(s) timed out or failed.
```

The TTL column tells you how long a stale resolver may keep the old answer (Google above:
about 29 minutes).

## Contents

- [Features](#features)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Expected values](#expected-values)
- [Watch mode and CI](#watch-mode-and-ci)
- [Email authentication checks](#email-authentication-checks)
- [Resolvers](#resolvers)
- [JSON output](#json-output)
- [Exit codes](#exit-codes)
- [Python API](#python-api)
- [FAQ](#faq)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Features

- **A, AAAA, CNAME, MX, TXT, NS, CAA and SOA** records, several types in one run
- **24 built-in public resolvers** in four regions, queried concurrently (a full run takes
  about as long as the slowest resolver), plus your own resolvers on the command line or in a file
- **Plain DNS (UDP with TCP fallback), TCP only, or DNS over HTTPS** (`--doh`), handy on
  networks that intercept port 53
- **Propagation %** against an expected value (`--expect`), "record is gone" checks
  (`--expect-absent`) and **authoritative baselines** (`--authoritative`): the expected value
  is taken from the zone's own name servers
- **Consistency %**: how many resolvers agree on the majority answer, with no expected value needed
- **Watch mode** that polls until the change is everywhere (or a deadline passes) and
  **exit codes** made for CI
- **Email checks**: MX, SPF (syntax, `+all`, recursive 10-lookup limit, void lookups, loops),
  DMARC (every tag, policy, report addresses) and DKIM (selectors, base64, RSA key size, Ed25519,
  revoked keys), with common selectors probed automatically
- **JSON output** for scripts and dashboards, colours only on a terminal (`NO_COLOR` respected)
- One dependency ([dnspython](https://www.dnspython.org/)), no API keys, no account, no tracking

## Quick start

### Docker

```bash
docker run --rm ghcr.io/saizul/dns-propagation example.com A
docker run --rm ghcr.io/saizul/dns-propagation watch www.example.com CNAME --expect example.netlify.app
docker run --rm ghcr.io/saizul/dns-propagation email example.com
```

### pipx / pip

```bash
pipx install git+https://github.com/saizul/dns-propagation
dns-propagation example.com MX
dns-propagation example.com A AAAA --authoritative
dns-propagation resolvers
```

Python 3.11 or newer is needed.

## Usage

```text
dns-propagation [check] NAME [TYPE ...] [options]       query every resolver once (default command)
dns-propagation watch NAME [TYPE ...] [options]         repeat until propagated
dns-propagation email DOMAIN [--selector S ...]         MX, SPF, DMARC, DKIM checks
dns-propagation resolvers [--region R] [--json]         list the built-in resolvers
```

| Option | Description |
| --- | --- |
| `TYPE ...`, `-t/--type` | Record types, default `A`. `A AAAA`, `-t mx -t txt` and `-t A,AAAA` all work |
| `-e/--expect VALUE` | Expected answer; repeat it (or use commas) for several values. One record type only |
| `--expect-absent` | Expect NXDOMAIN or an empty answer (the record was deleted) |
| `-a/--authoritative` | Ask the zone's authoritative name servers and expect their (majority) answer |
| `--match exact\|contains` | `exact` (default): the answer set must equal the expected set. `contains`: expected values must be present, extra answers are fine |
| `--threshold PCT` | Percent of resolvers that must match (or agree, without an expected value) to pass. Default 100 |
| `-r/--resolvers IDS` | Comma separated resolver ids (`cloudflare,google-2`) or provider names (`cisco`). Default: all |
| `--region R` | Only `global`, `na`, `eu` or `asia` resolvers, or a country code (`cn`, `jp`) |
| `--no-filtering` | Skip resolvers that block malicious or ad domains (Quad9, AdGuard, CleanBrowsing, Comodo) |
| `--resolver [NAME=]ADDR` | Add your own resolver: an IP address or a DoH URL. Without `-r`/`--region` only custom resolvers are queried |
| `--resolvers-file FILE` | Replace the built-in list with a file, see [`examples/resolvers.txt`](examples/resolvers.txt) |
| `--transport udp\|tcp\|doh\|all`, `--doh`, `--tcp` | How to reach resolvers. `all` queries each resolver over UDP and DoH |
| `--timeout SECONDS` | Per query timeout, default 3 |
| `--workers N` | Parallel queries, default 32 |
| `--json`, `--no-color`, `--wide` | Output options. `--wide` disables truncation of long TXT answers |
| `watch`: `--interval`, `--max-wait`, `--table` | Seconds between rounds (30), give up after (3600), print the full table every round |

## Expected values

Values are normalised before comparing, so `Mail.Example.COM` equals `mail.example.com.`.

| Type | `--expect` format | Notes |
| --- | --- | --- |
| `A`, `AAAA` | `203.0.113.10`, `2001:db8::10` | IPv6 is compared in compressed form |
| `CNAME`, `NS` | `target.example.net` | The trailing dot is optional |
| `MX` | `10 mx.example.com` or `mx.example.com` | Without a preference any preference matches |
| `TXT` | `v=spf1 include:_spf.example.net -all` | Long records split into several strings are joined first. Commas are not split for TXT |
| `CAA` | `0 issue letsencrypt.org` or `issue letsencrypt.org` | Quotes are optional |
| `SOA` | `2026111901` | A bare number compares only the serial, perfect for "did the new zone version arrive?" |

`--authoritative` finds the zone by walking up from the name (`www.shop.example.com`,
`shop.example.com`, `example.com`), asks a public resolver for the NS records, and then
queries every name server directly with recursion off. If they disagree, the majority wins
and a note is printed.

## Watch mode and CI

```bash
# Block a pipeline until 90% of public resolvers see the new address, at most 30 minutes.
dns-propagation watch app.example.com A --expect 203.0.113.10 \
  --threshold 90 --interval 30 --max-wait 1800
```

```text
round 1: A 41.7% (10/24) waiting
round 2: A 79.2% (19/24) waiting
round 3: A 91.7% (22/24) done
```

A complete GitHub Actions job is in
[`examples/github-actions-wait-for-dns.yml`](examples/github-actions-wait-for-dns.yml), and a
typical "I just moved my site" session in [`examples/after-dns-change.sh`](examples/after-dns-change.sh).

## Email authentication checks

```bash
dns-propagation email example.com                    # probes common DKIM selectors
dns-propagation email example.com -s google -s s1    # check specific selectors
dns-propagation email example.com --only spf,dmarc --json
```

| Check | What is verified |
| --- | --- |
| MX | Records exist, null MX (RFC 7505), NXDOMAIN |
| SPF | Exactly one `v=spf1` record; every mechanism and modifier; IPv4/IPv6 ranges; `+all` (error) and `?all`; `ptr` (deprecated); terms after `all`; `redirect` next to `all`; DNS lookups counted through every `include` and `redirect` (limit 10, `--no-recursive-spf` to count only the top level); void lookups (limit 2); include loops; includes without an SPF record |
| DMARC | Exactly one record at `_dmarc.DOMAIN`; `v=DMARC1` first; `p`, `sp`, `np` values; `pct`, `adkim`, `aspf`, `fo`, `ri`, `rf`; `rua`/`ruf` must be `mailto:`; warnings for `p=none`, `pct<100`, missing `rua`, unknown tags |
| DKIM | Key at `SELECTOR._domainkey.DOMAIN`; `v=DKIM1` first; `k=rsa` or `ed25519`; valid base64; RSA key size (error under 1024 bits, warning under 2048); Ed25519 key length; revoked keys (`p=`); `h=sha1` only; `t=y` testing mode |

Findings are `ok`, `info`, `warning` or `error`. The command exits with 1 when there is at least
one error. The lookups go to Cloudflare by default; use `--resolver 9.9.9.9`, `--doh` or `--tcp`
to change that.

## Resolvers

`dns-propagation resolvers` prints the built-in list:

| Region | Resolvers |
| --- | --- |
| `global` | Cloudflare (2), Google (2), Quad9 (2), OpenDNS (2), AdGuard, Control D, CleanBrowsing |
| `na` | Lumen (Level 3), Hurricane Electric, Comodo Secure DNS, UltraDNS Public |
| `eu` | DNS4EU (unfiltered), Mullvad (DoH only), Yandex |
| `asia` | AliDNS, DNSPod, 114DNS, Quad101 (Taiwan), KT (Korea), IIJ (Japan, DoH only) |

Resolvers tagged `filtering` block malware or ad domains; use `--no-filtering` when a blocked
answer would look like a propagation problem. Public resolvers come and go: if one stops
answering, please [open an issue](https://github.com/saizul/dns-propagation/issues/new/choose).

Anycast resolvers answer from the instance nearest to **you**, so a run from Europe does not
show what a Google instance in Australia has cached. For a truly global view, run the
container from several regions (for example a CI matrix) and compare the JSON.

## JSON output

`--json` prints one document (see [`examples/sample-check.json`](examples/sample-check.json)):

```json
{
  "tool": "dns-propagation",
  "version": "0.1.0",
  "propagated": false,
  "checks": [
    {
      "name": "example.com",
      "type": "A",
      "expected": {"values": ["203.0.113.10"], "absent": false, "mode": "exact", "source": "cli"},
      "threshold": 100.0,
      "resolvers": [
        {"id": "cloudflare", "name": "Cloudflare", "provider": "Cloudflare", "region": "global",
         "country": "", "transport": "udp", "endpoint": "1.1.1.1", "status": "ok",
         "rcode": "NOERROR", "answers": ["203.0.113.10"], "ttl": 300, "elapsed_ms": 18.4,
         "error": "", "matches": true}
      ],
      "summary": {"total": 4, "responded": 3, "matching": 2, "propagation_pct": 50.0,
                  "consistency_pct": 66.7, "majority": {"status": "ok", "answers": ["203.0.113.10"]},
                  "propagated": false},
      "notes": []
    }
  ]
}
```

`status` is one of `ok`, `nxdomain`, `noanswer`, `servfail`, `refused`, `timeout`, `error`.
`watch --json` adds `rounds`. The `email --json` document has `records`, `findings` and `summary`.

## Exit codes

| Code | `check` / `watch` | `email` |
| --- | --- | --- |
| 0 | Propagated: the threshold is reached | No errors |
| 1 | Not propagated (or resolvers disagree) | At least one error finding |
| 2 | Usage error: bad option, record type, expected value or resolver | Usage error |
| 3 | No resolver answered, or the authoritative servers could not be found | Every lookup failed |

## Python API

```python
from dns_propagation import BUILTIN, DnsQuerier, Expectation, run_check
from dns_propagation.resolvers import targets_for

report = run_check(
    "example.com",
    "A",
    targets_for(BUILTIN, "udp"),
    DnsQuerier(),
    Expectation.build("A", ["203.0.113.10"]),
    threshold=90,
)
print(report.propagation_pct, report.propagated)
for row in report.results:
    print(row.target.label, row.result.status, row.result.answers)
```

Any callable `(target, name, rdtype, timeout) -> QueryResult` can replace `DnsQuerier`,
which is how the test suite runs without a network.

## FAQ

**Why do resolvers disagree right after I changed a record?** Each resolver caches the old
answer until its TTL runs out. The TTL column shows the remaining time. Lower the TTL a day
before a planned migration and changes will spread in minutes.

**Is "propagation" even real?** Strictly, DNS does not push changes; resolvers re-fetch
when their cache expires. "Propagated" here means "the resolvers you asked now return the new
answer", which is what matters for your users.

**Why does a resolver show SERVFAIL or REFUSED?** SERVFAIL often means a DNSSEC problem
(broken signatures after a provider change) or unreachable name servers. Some networks also
intercept or block outgoing port 53; try `--doh`.

**`--authoritative` says the servers answered SERVFAIL, but the domain works.** Your network
may be redirecting port 53 to its own resolver, which refuses non-recursive queries. Try
`--tcp`, or run from somewhere else (for example a CI runner).

**Can I check my internal resolvers?** Yes: `--resolver office=10.0.0.53` or a
`--resolvers-file`. DoH resolvers with a path (NextDNS, a Pi-hole with DoH) work too.

**Does it send my domains anywhere else?** Only to the resolvers you query (and, for
`--authoritative`, the zone's name servers). There is no telemetry.

## Roadmap

Items marked **good first issue** are small and well scoped; see
[CONTRIBUTING.md](CONTRIBUTING.md#good-first-issues).

- [ ] **good first issue** More record types: `SRV`, `PTR`, `DS`, `DNSKEY`, `HTTPS`/`SVCB`
- [ ] **good first issue** `--format csv` and `--format markdown` for reports and tickets
- [ ] **good first issue** Show the remaining TTL as a human duration ("29m") in the table
- [ ] **good first issue** DNS over TLS transport (`--dot`) using `dns.query.tls`
- [ ] **good first issue** BIMI and MTA-STS / TLS-RPT presence checks for `email`
- [ ] **good first issue** IPv6 addresses for the built-in resolvers (`--ipv6`)
- [ ] EDNS Client Subnet to ask Google and others "as if" from another region
- [ ] DNSSEC validation status per resolver (AD flag) and a `--dnssec` check
- [ ] A small web UI / HTTP endpoint mode for the container

## Contributing

Contributions of all sizes are welcome: a new resolver, a record type, a better error message.
Read [CONTRIBUTING.md](CONTRIBUTING.md) for setup, the project layout and beginner issues,
and follow the [Code of Conduct](CODE_OF_CONDUCT.md). Security problems: see [SECURITY.md](SECURITY.md).

```bash
git clone https://github.com/saizul/dns-propagation
cd dns-propagation
python -m venv .venv && . .venv/bin/activate
pip install -e .[dev]
pytest
ruff check . && ruff format --check .
```

## License

[MIT](LICENSE) © Saizul Amin
