# Security Policy

## Reporting a vulnerability

Open a private security advisory on GitHub (Security → Advisories → Report a
vulnerability). Do not open public issues for suspected vulnerabilities.

## Data-handling policy (contributors)

Firewall configurations and tech support files are sensitive: they contain
addressing, topology, policy logic, and occasionally secrets.

- **Never commit** real device configurations, tech support files, or BPA reports
  derived from them — not even redacted ones. This includes test fixtures.
- Unit tests use only small, synthetic, hand-written configs under `testdata/`.
- Conformance tests read real fixtures from the path in `OPENPANBPA_FIXTURES`,
  which must live outside the repository. They skip when the variable is unset.
- The `.gitignore` and gitleaks configuration enforce this defensively
  (`*.tgz`, `*techsupport*`, `fixtures/`), but the responsibility is yours first.

## Threat model notes

- The tool is designed to run in air-gapped environments: the binary performs
  **no network I/O** at runtime. Any change introducing network access must be
  called out in its PR and will receive security review.
- Archive ingestion reads selected entries into memory only; nothing from an
  archive is written to disk (no extraction-path traversal surface).
