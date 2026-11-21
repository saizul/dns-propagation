# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `email` checks MTA-STS (`_mta-sts.DOMAIN`, RFC 8461) and SMTP TLS reporting
  (`_smtp._tls.DOMAIN`, RFC 8460) records: version tag first, `id` syntax, `rua` URIs,
  duplicate records and tags. Missing records are reported as `info`, so they never fail the
  command; MTA-STS without TLS-RPT is a warning. Select them with `--only mta-sts,tls-rpt`.
- `EMAIL_CHECKS`, `validate_mta_sts()` and `validate_tls_rpt()` in `dns_propagation.emailauth`.

### Changed

- `email` and `check_domain()` run the two new checks by default, so reports contain
  `mta-sts` and `tls-rpt` findings and records.

## [0.1.0] - 2026-11-19

### Added

- `check` (default command): query A, AAAA, CNAME, MX, TXT, NS, CAA and SOA records on
  24 built-in public resolvers concurrently and print a propagation table with status,
  TTL, response time and answers.
- Transports: UDP with TCP fallback, TCP only (`--tcp`) and DNS over HTTPS (`--doh`),
  or UDP and DoH together (`--transport all`).
- Expected values with normalisation per record type (`--expect`), `exact` and
  `contains` matching, SOA serial-only matching, MX without preference,
  `--expect-absent` for deleted records and `--authoritative` to take the expected value
  from the zone's own name servers.
- Propagation and consistency percentages, a pass threshold and CI exit codes
  (0 propagated, 1 not propagated, 2 usage error, 3 DNS failure).
- `watch`: repeat the check until propagated or `--max-wait` passes.
- `email`: MX, SPF (syntax, recursive lookup limit, void lookups, loops), DMARC and DKIM
  (RSA key size, Ed25519, revoked keys, common selector probing) checks.
- Resolver selection by id, provider, region, country and filtering tag; custom resolvers
  from the command line or a file.
- `--json` output for every command, `resolvers` command, Python API.
- Container image on `ghcr.io/saizul/dns-propagation` (non-root).

[Unreleased]: https://github.com/saizul/dns-propagation/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/saizul/dns-propagation/releases/tag/v0.1.0
