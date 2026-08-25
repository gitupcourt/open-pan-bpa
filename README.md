# open-pan-bpa

Offline, air-gapped Best Practice Assessment for Palo Alto Networks NGFW configurations.

> [!IMPORTANT]
> **This is not an official Palo Alto Networks product.** It is an independent,
> community-built tool with no affiliation to, sponsorship by, or endorsement from
> Palo Alto Networks, Inc. "Palo Alto Networks", "PAN-OS", "Panorama", and related
> marks are trademarks of Palo Alto Networks, Inc. Best-practice guidance implemented
> here is independently derived from Palo Alto Networks' publicly available
> documentation; assessment results are advisory and provided without warranty.

## Why

Every incarnation of the vendor BPA (the original support-portal tool → AIOps for NGFW →
Strata Cloud Manager posture) is SaaS: your full firewall configuration is uploaded
to a cloud you don't control. For air-gapped and regulated networks that's a
non-starter. `open-pan-bpa` evaluates best-practice checks **entirely offline**:

- **Input:** a PAN-OS tech support file (`.tgz`) or an exported XML
  configuration — from a firewall or from Panorama.
- **Engine:** a single static binary. No container runtime, no Python — copy
  it to a jump box and run it. `bpa scan` performs no network I/O under any
  circumstances.
- **Output:** self-contained HTML report, versioned JSON, and CSV.

## Quick start

```
bpa scan techsupport.tgz --out report/
bpa scan running-config.xml --format json,html,csv
```

See [USAGE.md](USAGE.md) for the full guide: getting binaries, generating
input files on the firewall, output formats, verdict semantics, and custom
check packs.

## Two engines, one report format

For environments where uploading the configuration is acceptable, the binary
can alternatively submit it to **Palo Alto Networks' official hosted BPA
(posture) API** and report *their* engine's verdicts in the same formats:

```
bpa api-scan techsupport.tgz --out report/
```

`api-scan` is a **separate subcommand by design** — the offline guarantee of
`scan` is absolute and shares no code path with it. It states loudly that it
uploads the config before doing so, takes credentials from environment
variables only, and supports the API's server-side config deletion flag.
Both modes emit the same schema-versioned report, so results are directly
comparable. See [USAGE.md](USAGE.md) §4 for credential setup (documented by
Palo Alto Networks on [pan.dev](https://pan.dev/sase/docs/service-accounts/))
and the full flag set.

## Where the best practices come from

None of the check criteria are invented here. Every one of the checks is
grounded in **Palo Alto Networks' publicly available documentation** — the
[Best Practices portal](https://docs.paloaltonetworks.com/best-practices) and
the product administration guides on
[docs.paloaltonetworks.com](https://docs.paloaltonetworks.com):

- **Every check carries `references`** — the specific doc page(s) it
  implements — in its YAML pack definition, in the JSON/CSV output, and as
  clickable `[doc N]` links in the HTML report next to each check and each
  failing finding. If you want to verify why a check says what it says, the
  primary source is one click away.
- **Every check carries a `rationale`** explaining the risk in plain terms.
- A test enforces this: a check without documentation references or a
  rationale does not build.
- Vendor doc URLs move; a weekly automated link-health scan verifies every
  reference still resolves and flags redirects so links stay canonical.
- The check *text* is independently written from those public sources — no
  vendor report content is reproduced.

Where current documentation is ambiguous, semantics are settled by observed
assessment behavior and the discrepancy is recorded in
[docs/open-questions.md](docs/open-questions.md) rather than guessed at.

## Design

- Checks are **declarative YAML packs** (embedded in the binary, overridable with
  `--packs`) plus registered Go evaluators for cross-cutting analysis.
- Volatile reference data (URL categories, decoder lists, thresholds) ships as
  **versioned data packs**, not code.
- Verdicts are honest: allow-only checks skip deny rules, disabled rules and
  read-only predefined objects downgrade to notes, and every finding names the
  actual failing fields.
- Stable check identity is a **slug**, not a numeric ID.

## Development

```
go build ./...
go test ./...
```

Conformance ("golden") tests run against real-device fixtures that are **never
committed** — real firewall configurations are treated as sensitive regardless
of where they came from. Point `OPENPANBPA_FIXTURES` at a local
fixtures directory to enable them; they skip cleanly when unset. See
[SECURITY.md](SECURITY.md) for the data-handling policy.

## License

MIT — see [LICENSE](LICENSE).
