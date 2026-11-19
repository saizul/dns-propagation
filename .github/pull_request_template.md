## What does this pull request do?

<!-- One or two sentences. Link the issue: "Closes #123". -->

## Type

- [ ] New or updated resolver
- [ ] Propagation check, watch mode or output
- [ ] Email authentication checks (SPF, DMARC, DKIM, MX)
- [ ] Bug fix
- [ ] Documentation

## Checklist

- [ ] Tests added or updated (`pytest` passes; tests use `FakeQuerier` or `dns.message.from_text`, never the network)
- [ ] `ruff check . && ruff format --check .` passes
- [ ] New resolvers link to the operator's documentation and have the right region, country and tags
- [ ] JSON output stays backwards compatible (new fields only; no renamed or removed fields)
- [ ] README updated for new options
- [ ] CHANGELOG.md updated under "Unreleased"
