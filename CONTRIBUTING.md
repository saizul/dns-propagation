# Contributing to dns-propagation

Thank you for helping! New resolvers, record types, checks, documentation and bug reports
are all welcome.

- [Ways to contribute](#ways-to-contribute)
- [Good first issues](#good-first-issues)
- [Development setup](#development-setup)
- [Project layout](#project-layout)
- [Add a resolver](#add-a-resolver)
- [Add a record type](#add-a-record-type)
- [Guidelines](#guidelines)
- [Pull request process](#pull-request-process)

## Ways to contribute

| Size | Idea |
| --- | --- |
| 10 minutes | Fix a typo, clarify an option, add a FAQ entry, report a dead resolver |
| 30 minutes | Add a resolver, improve an error message, add a missing test case |
| 1-2 hours | One of the good first issues below |
| Larger | EDNS Client Subnet, DNSSEC status, an HTTP mode (open an issue first) |

Comment on an issue before you start so nobody else picks the same one.

## Good first issues

Each of these is self-contained and touches one or two files plus tests.

1. **Human-readable TTLs.** Show `29m`, `2h 5m` or `1d` in the TTL column; keep the raw
   number in JSON. (`output.py`, `tests/test_output.py`)
2. **`--format csv` and `--format markdown`.** One row per resolver with the same columns
   as the table, for tickets and spreadsheets. (`cli.py`, `output.py`, tests)
3. **SRV and PTR records.** Add them to `RECORD_TYPES`, normalise answers
   (`10 5 5060 sip.example.com.`) and expected values, and accept `dns-propagation 192.0.2.1 PTR`
   by turning the address into its `in-addr.arpa` / `ip6.arpa` name. (`records.py`, tests)
4. **DNS over TLS.** A `dot` transport using `dns.query.tls` on port 853 and a `dot` field for
   resolvers that support it (Cloudflare `one.one.one.one`, Google `dns.google`, Quad9
   `dns.quad9.net`). (`resolvers.py`, `query.py`, tests with a fake querier)
5. **BIMI record check.** `default._bimi.DOMAIN` with `v=BIMI1; l=https://...svg; a=...`;
   warn when DMARC is not `quarantine` or `reject` (BIMI requires it). (`emailauth.py`, tests)
6. **IPv6 resolver addresses.** Add an `address6` field to the built-in resolvers and an
   `--ipv6` flag that queries them instead of IPv4. (`resolvers.py`, `cli.py`, tests)
7. **Stop early in `watch` on SERVFAIL everywhere.** If every resolver answers SERVFAIL for
   three rounds in a row, print a DNSSEC hint and exit with 1 instead of waiting.
   (`check.py`, `cli.py`, tests)

## Development setup

```bash
git clone https://github.com/saizul/dns-propagation
cd dns-propagation
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e .[dev]
pytest
ruff check . && ruff format --check .
docker build -t dns-propagation:dev .
```

Python 3.11+ is needed. **Tests never touch the network.** Use `FakeQuerier` from
`tests/conftest.py` for anything above the query layer, and `dns.message.from_text` to build
real DNS responses for `parse_response` (see `tests/test_records.py`). Watch-mode tests pass
a fake `sleep` and `clock`.

To try your change for real:

```bash
dns-propagation example.com A AAAA MX
dns-propagation example.com A --doh --no-filtering
dns-propagation email example.com
```

## Project layout

| Path | Responsibility |
| --- | --- |
| `src/dns_propagation/resolvers.py` | `Resolver`, `Target`, the `BUILTIN` list, selection, custom resolvers and files |
| `src/dns_propagation/records.py` | Supported record types, normalising answers and expected values, matching |
| `src/dns_propagation/query.py` | `QueryResult`, `parse_response`, `DnsQuerier` (UDP/TCP/DoH via dnspython) |
| `src/dns_propagation/check.py` | `Expectation`, `run_check` (thread pool), `Report` summaries, authoritative baseline, `watch` |
| `src/dns_propagation/emailauth.py` | MX, SPF, DMARC and DKIM checks |
| `src/dns_propagation/output.py` | Tables, colours, JSON documents |
| `src/dns_propagation/cli.py` | `argparse` commands and exit codes |
| `tests/` | pytest suite; `conftest.py` has `FakeQuerier` and helpers |

## Add a resolver

1. The resolver must be **free, public, documented by its operator** and usable without an
   account. Link the documentation in your pull request.
2. Add a `Resolver(...)` line to `BUILTIN` in `resolvers.py`: a unique lower-case `id`, display
   name, provider, region (`global` for anycast networks, otherwise `na`, `eu` or `asia`),
   ISO country code, IPv4 address and DoH URL (empty string if there is none). Add
   `("filtering",)` if it blocks domains by default.
3. Check it by hand: `dns-propagation example.com -r YOUR_ID` and with `--doh`.
4. Update the region table in `README.md` and add a line to `CHANGELOG.md`.
   `test_builtin_list_is_well_formed` checks ids, addresses and URLs.

## Add a record type

1. Add the type to `RECORD_TYPES` in `records.py`.
2. Teach `normalize_rdata` how to turn the dnspython rdata into canonical text, and
   `normalize_expected` how to parse what a user types. Keep both lower-case for names and
   with trailing dots.
3. Add tests in `tests/test_records.py`: a response built with `dns.message.from_text`, valid
   and invalid expected values.
4. Add a row to the "Expected values" table in `README.md`.

## Guidelines

- The only runtime dependency is dnspython; discuss new ones first.
- Keep the JSON output backwards compatible: add fields, never rename or remove them.
- Escape everything that comes from DNS before printing it (`output.clean`).
- Type hints everywhere; `ruff check` and `ruff format` clean.
- Tests are fast and deterministic: no network, no `sleep`.

## Pull request process

1. Fork and create a branch (`resolver/nextdns`, `feature/srv-records`, `fix/mx-trailing-dot`).
2. Keep pull requests focused; fill in the checklist in the template.
3. Add an entry to `CHANGELOG.md` under "Unreleased".
4. A maintainer reviews within a few days.

By contributing you agree that your work is released under the MIT License and
that you follow the [Code of Conduct](CODE_OF_CONDUCT.md).
