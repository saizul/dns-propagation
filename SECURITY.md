# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | yes |

## What counts as a vulnerability

- A crafted DNS or DoH response that crashes the tool, makes it hang past its timeouts or
  exhausts memory
- A crafted record (TXT, CAA, DKIM key) that injects terminal escape sequences or breaks
  the JSON output
- Queries sent to a host other than the selected resolvers, the zone's authoritative name
  servers (`--authoritative`) or the resolver chosen for `email`
- TLS certificate checks being skipped for DNS over HTTPS
- The container running as root or containing secrets

Wrong answers from a public resolver, or a resolver being down, are not vulnerabilities;
please open a normal issue.

## Reporting

Please **do not** open a public issue. Use
[GitHub private vulnerability reporting](https://github.com/saizul/dns-propagation/security/advisories/new)
with the version, the impact and steps to reproduce (a captured response or a zone file
snippet is ideal).

You will get an answer within 5 working days. Fixes are released as soon as
possible and credited in the changelog unless you prefer otherwise.
