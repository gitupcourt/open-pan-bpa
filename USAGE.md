# Using open-pan-bpa

> Not an official Palo Alto Networks product. Results are advisory; validate
> changes in your own change-control process.

## 1. Get the binary

Grab the archive for your platform from the GitHub **Releases** page and unpack
it — the binary is the entire product. No installer, no runtime, no container,
no network access required or attempted.

| Platform | File |
|---|---|
| Windows x64 | `bpa_windows_amd64.zip` |
| Linux x64 | `bpa_linux_amd64.tar.gz` |
| Linux ARM64 | `bpa_linux_arm64.tar.gz` |
| macOS (Apple silicon) | `bpa_darwin_arm64.tar.gz` |

Verify the download against `checksums.txt` from the same release:

```
sha256sum -c checksums.txt --ignore-missing
```

Building from source instead: install Go 1.24+, then `go build ./cmd/bpa`.

For air-gapped use, transfer the verified archive by your approved media
process. The binary makes zero network calls at runtime, so it can run
directly on a management jump box.

## 2. Get an input file

`bpa` assesses both **firewall** configurations (single- or multi-vsys) and
**Panorama** configurations. Panorama inputs are detected automatically: the
device-group hierarchy (including parent relationships), shared and per-group
pre/post rulebases, and template/template-stack device configuration are all
evaluated, with findings attributed to the device group or template they came
from.

`bpa` accepts either of the following, produced on the firewall:

**A tech support file (`.tgz`)** — Device → Support → Generate Tech Support
File, then Download. (CLI: `request tech-support dump`, then
`scp export tech-support to user@host:/path`.) `bpa` reads only the
configuration inside the archive and automatically prefers the merged running
config, which includes Panorama-pushed policy.

**A configuration XML export** — Device → Setup → Operations → Export named
configuration snapshot (`running-config.xml`).

Prefer the tech support file: some checks (e.g. license expiry) rely on device
state that only the TSF carries. With a bare XML export those checks don't
fail or silently vanish — they report an advisory note explaining that a TSF
is needed to assess them.

Treat both artifacts as sensitive: they contain your addressing, topology, and
policy logic. Don't commit them to version control or leave them in downloads
folders — that hygiene is yours to enforce; `bpa` never copies or transmits
them.

## 3. Run a scan

```
bpa scan techsupport.tgz --out report/
```

```
bpa scan running-config.xml --format json,html,csv --out report/
```

Flags (before or after the input file, either works):

| Flag | Default | Meaning |
|---|---|---|
| `--out DIR` | `.` | Output directory (created if missing) |
| `--format LIST` | `json,html` | Any of `json`, `html`, `csv`, comma-separated |
| `--packs DIR` | built-in | Load check packs from a directory instead of the embedded set |

The scan prints a one-line summary and writes `bpa-<hostname>.<ext>` files:

- **`.html`** — the human report: summary cards, per-check results, failed
  findings with the exact offending fields. Self-contained; open in any
  browser, works offline.
- **`.json`** — machine-readable, schema-versioned (`schema_version` field);
  the stable contract for automation and integrations.
- **`.csv`** — one row per finding, for spreadsheets.

## 4. Read the verdicts

| Verdict | Meaning |
|---|---|
| `pass` | The object meets the best-practice expectation |
| `fail` | It doesn't; `failed_fields` names exactly what to change |
| `note` | Advisory: real observation, deliberately not a hard fail (e.g. a failing setting on a *disabled* rule, or individually attached profiles where a group is preferred) |
| `n/a` | Check doesn't apply to this object (e.g. allow-only checks skip deny rules) |

Severities (`critical`, `high`, `warning`, `informational`) rank how much a
`fail` matters; fix criticals first.

## 5. Custom check packs

Copy the embedded pack as a starting point (see `packs/core.yaml` in the
source tree), edit thresholds or drop checks, and run with `--packs ./mypacks`.
Every check needs a unique `slug`; params like `min_length` are tunable per
your policy. The pack format is YAML and validated on load.

## 6. Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed (regardless of findings) |
| 1 | Error (unreadable input, bad pack, write failure) |
| 2 | Usage error |

A `--fail-on <severity>` gate for CI pipelines is on the roadmap.
