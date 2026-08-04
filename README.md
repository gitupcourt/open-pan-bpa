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
- **Engine:** a single static binary. No container runtime, no Python, no network
  access — copy it to a jump box and run it.
- **Output:** self-contained HTML report, versioned JSON, and CSV.

## Quick start

```
bpa scan techsupport.tgz --out report/
bpa scan running-config.xml --format json,html,csv
```

See [USAGE.md](USAGE.md) for the full guide: getting binaries, generating
input files on the firewall, output formats, verdict semantics, and custom
check packs.

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
