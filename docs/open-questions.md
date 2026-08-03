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
| 2 | `av-inline-ml-models`, `as/vp-inline-cloud-engines` (272/334/360) | Every inline-ML model/engine must be a **blocking** action; alert-only fails | Set one AV Inline ML model to "enable (alert-only)" while leaving Inline Cloud Analysis on; re-run reference |
| 3 | `uf-block-liability` / `uf-cred-liability` (340/344) | Liability list is exactly: abused-drugs, adult, copyright-infringement, extremism, gambling, peer-to-peer, questionable, weapons | Block 7 of the 8 (drop copyright-infringement); if reference still passes, its list is smaller |
| 4 | `du-sync-peer-*` (191/192) | Non-HA devices pass trivially; HA devices need sync-to-peer **yes** | Confirmed direction on HA homegateways; the non-HA branch is unverified (PA-220 had no reference coverage here) |
| 5 | `sprof-tacplus-chap` (234) | Protocol must be CHAP; no failing reference instance seen | Set a TACACS+ profile to PAP on a lab box (profile only, no server needed) |
| 6 | `cert-trust-untrust-split` (267) | Fails only when one cert is BOTH forward-trust and forward-untrust CA | Configure the same CA for both roles in a lab decryption setup |
| 7 | `authseq-secondary` (159) | A sequence with <2 profiles fails | Create a one-profile authentication sequence |
| 8 | `dev-telemetry-sharing` (197) | Fails only when every telemetry setting is explicitly "no" | Disable all telemetry options; re-run reference |
| 9 | `ls-system-*` / `ls-config` (177/178/182) | A destination-bearing match with filter "All Logs" (or matching severity words) covers; no failing instance seen | Remove system/config log forwarding on a lab box |
| 10 | `wf-forward-everything` (47) | Needs a rule with app=any, file-type=any, direction=both | Restrict a WildFire profile to upload-only; re-run reference |

| 11 | `zpp-packet-attack` (87) | Element spellings for the three packet-based protections are guessed (multiple candidates accepted); absent = fail matches all fixtures | Enable malformed-option discard, overlapping-TCP-segment-mismatch discard, and TCP timestamp stripping in a lab Zone Protection profile → grounds the exact XML names |
| 12 | `gpgw-client-auth` (77) | Fails only when neither certificate profile nor auth profile exists; no failing reference instance seen | Create a lab GP gateway with no client auth |
| 13 | `ha-aa-*` (147/148) | Active/Active branch entirely unverified (all fixtures are A/P) | If an A/A lab pair is ever available; low priority |
| 14 | `crypto` KEM asymmetry (358/359/376) | IKE profiles without AKE rounds pass; IPsec profiles without AKE fail (defaults are DH). Inferred from all-pass/all-fail split | Add a KEM AKE round to a lab IPsec profile → confirms the pass path |

## Reference-engine inconsistencies (documented deviations, not questions)

- **HA2 keep-alive (145)**: two devices with byte-identical normalized
  keep-alive config (`enabled: no`) received opposite verdicts from the
  reference engine (PA-850s pass, PA-460/VM/PA-220 fail) — possibly
  model-metadata-dependent. We always fail disabled keep-alive; allowlisted.

## Parked (not implemented — element names or semantics unground)

- **98** Buffered log forwarding (Panorama-buffered): could not ground the XML
  element in any fixture config; all references pass. Needs a config where
  it's explicitly disabled, or a pointer to the element name.
- **377** PQC (ML-KEM) for management TLS profiles: 12.1-only; needs an
  SSL/TLS service profile with PQC settings present in a fixture.
- **92 (partial)** External auth for administrators: account-level profiles
  confirmed; whether an *unused* device-wide auth setting alone passes is
  unverified.
- **164/165/231** User-ID (client probing, timeout, certificate profile):
  every fixture passes all three with minimal/no User-ID config, so the fail
  conditions are unobservable. Needs a lab config with WMI client probing
  enabled and/or a User-ID collector configured without a certificate
  profile.

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
