# Open questions — checks needing boundary evidence

Living list of checks whose semantics could not be fully pinned by the
reference fixtures (no pass **and** fail instance observed at the boundary).
Each entry says what to configure on a **lab** firewall to settle it: apply
the config, generate a TSF, run it through the reference API, and drop both
into the fixtures folder — the conformance harness does the rest.

Resolved entries move to the bottom with the verdict.

## Needs a lab test config

| # | Check(s) | What we assume today | Lab config that settles it |
|---|---|---|---|
| 1 | `uf-category-logging` / `uf-cred-logging` (196/346) | Any category (or credential category) set to **allow** fails | Set one URL category to Allow (e.g. web-advertisements) and one credential-submission category to Allow; re-run reference |
| 3 | `uf-block-liability` / `uf-cred-liability` (340/344) | Liability list is exactly: abused-drugs, adult, copyright-infringement, extremism, gambling, peer-to-peer, questionable, weapons | Block 7 of the 8 (drop copyright-infringement); if reference still passes, its list is smaller |
| 4 | `du-sync-peer-*` (191/192) | Non-HA devices pass trivially; HA devices need sync-to-peer **yes** | Confirmed direction on HA homegateways; the non-HA branch is unverified (PA-220 had no reference coverage here) |
| 8 | `dev-telemetry-sharing` (197) | Fails only when every telemetry setting is explicitly "no" | Disable all telemetry options; re-run reference |
| 11 | `zpp-packet-attack` (87) | Element spellings for the three packet-based protections are guessed (candidates accepted) | Enable the three protections in a lab Zone Protection profile → grounds exact XML names |
| 12 | `gpgw-client-auth` (77) | Fails only when neither certificate profile nor auth profile exists | Create a lab GP gateway with no client auth |
| 15 | `wf-forward-everything` (47) | Direction is NOT enforced (upload-only passes); download-only still unverified | Make a WildFire rule download-only; re-run reference |
| 16 | AID EDLs (398–409) | Predefined object identifiers + license Feature string unknown | Any TSF from a device with the Advanced IP Defense license |

## Resolved by lab boundary configs (2026-08-03 batch — thanks)

- **Item 2 — inline-ML engine actions (334)**: CONFIRMED. An alert-only
  engine fails the reference even with Inline Cloud Analysis on. Our check
  agreed once compared against the matching (non-stale) TSF.
- **Item 5 — TACACS+ CHAP (234)**: CONFIRMED. PAP fails; our check agrees.
- **Item 6 — Forward Trust/Untrust split (267)**: CONFIRMED, mechanism
  corrected. The role comes from the **ssl-decrypt certificate assignment**
  (rsa/ecdsa slots), not per-cert flags; assigning the same certs to both
  roles fails exactly those certs. Parser now reads both mechanisms.
- **Item 7 — single-profile auth sequence (159)**: CONFIRMED; our check agrees.
- **Item 9 — system log forwarding removal (177/178)**: CONFIRMED; our
  check agrees against the matching TSF.
- **Item 10 — WildFire direction**: FALSIFIED our assumption — an
  upload-only any/any rule PASSES the reference; direction requirement
  removed (download-only remains unverified, see item 15).
- **Also observed**: enabling VP Inline Cloud Analysis flips 365 to pass, as
  expected.

| 11 | `zpp-packet-attack` (87) | Element spellings for the three packet-based protections are guessed (multiple candidates accepted); absent = fail matches all fixtures | Enable malformed-option discard, overlapping-TCP-segment-mismatch discard, and TCP timestamp stripping in a lab Zone Protection profile → grounds the exact XML names |
| 12 | `gpgw-client-auth` (77) | Fails only when neither certificate profile nor auth profile exists; no failing reference instance seen | Create a lab GP gateway with no client auth |
| 13 | `ha-aa-*` (147/148) | Active/Active branch entirely unverified (all fixtures are A/P) | If an A/A lab pair is ever available; low priority |
| 14 | `crypto` KEM asymmetry (358/359/376) | IKE profiles without AKE rounds pass; IPsec profiles without AKE fail (defaults are DH). Inferred from all-pass/all-fail split | Add a KEM AKE round to a lab IPsec profile → confirms the pass path |

## Reference-engine inconsistencies (documented deviations, not questions)

- **HA2 keep-alive (145)**: two devices with byte-identical normalized
  keep-alive config (`enabled: no`) received opposite verdicts from the
  reference engine (PA-850s pass, PA-460/VM/PA-220 fail) — possibly
  model-metadata-dependent. We always fail disabled keep-alive; allowlisted.
- **Default-rule logging (12/13)**: the reference failed these on all six
  fixtures through 2026-08-02, including devices with correct overrides —
  then **passed byte-identical default rules on 2026-08-03**, indicating a
  server-side engine fix. Our semantics (pass when overridden with
  session-end logging) now match the fixed engine; the allowlist entries
  remain only to absorb pre-fix reference reports.

## Implemented but pass-path unverified (all fixtures fail)

These checks fail on every fixture, so only the fail branch is evidence-backed.
The logic is derived from the check titles and public docs; the pass path
would be confirmed by any device that actually satisfies them.

- **QUIC block (241)** — verified NOT gated on decryption being configured
  (devices with no decryption rules still fail). Pass path = an enabled deny
  rule with application `quic`.
- **New App-ID staging rule (249)**, **WildFire real-time signature hold
  (347)**, **GenAI deny rule (348)** — not implemented; see Parked below.
- **Advanced IP Defense EDL blocks (398–409)** — now IMPLEMENTED as
  license-aware checks (operator-confirmed: these six lists belong to the
  license-gated Advanced IP Defense subscription, which the reference engine
  fails everyone on without saying so). Semantics: list enforced → pass;
  license absent (or bare-XML input) → informational note; licensed but
  unused → fail. Two things still need grounding from a licensed device's
  TSF: the **exact predefined EDL object identifiers** (pack currently
  carries display-name candidates like "Advanced IP Defense: C2") and the
  **license Feature string** (we match case-insensitive "ip defense").

## Parked (not implemented — element names or semantics unground)

- **98** Buffered log forwarding (Panorama-buffered): could not ground the XML
  element in any fixture config; all references pass. Needs a config where
  it's explicitly disabled, or a pointer to the element name.
- **377** PQC (ML-KEM) for management TLS profiles: 12.1-only; needs an
  SSL/TLS service profile with PQC settings present in a fixture.
- **249** Rule allowing new App-IDs from content updates: requires resolving
  application-filter membership (the `new-app-id` filter), which needs
  predefined content data we don't ship yet.
- **347** WildFire real-time signature lookup / hold-for-verdict: the
  governing element does not appear in any fixture config; likely a device
  setting introduced in a version none of our fixtures set explicitly.
- **348** GenAI deny rule below the sanctioned-AI allow rule: requires
  application-filter resolution (`Gen AI Apps`) plus rule-order reasoning.
  Both are worth building once predefined content data lands.
- **398–409** Newer predefined EDL block rules (see above).
- **92 (partial)** External auth for administrators: account-level profiles
  confirmed; whether an *unused* device-wide auth setting alone passes is
  unverified.

## Resolved by reference evidence

- **File Blocking (45)**: block types must stay *within* the reference list
  (extras fail); partial coverage passes. Operator decision: default pack
  mirrors this; strict full-list variant goes to the docs-strict pack.
- **DNS Security (38/253)**: 38 = sinkhole on configured categories only
  (capture not enforced); 253 = C2 needs sinkhole + extended-capture, others
  sinkholed or captured.
- **Credential-risky categories (345)**: excludes encrypted-dns and
  scanning-activity (site-blocking-only additions).
- **SSL/TLS service profile (63)**: only the minimum version is enforced;
  an explicit max below "max" still passes.
- **External admin auth (92)**: evaluated on administrator accounts, not the
  device-wide setting.
- **Telemetry (197)**: a configured region counts as sharing enabled.
