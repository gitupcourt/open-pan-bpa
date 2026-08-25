# How open-pan-bpa compares to the hosted BPA

`bpa scan` (offline) and Palo Alto Networks' hosted BPA engine (reachable via
`bpa api-scan`) assess the same configurations, and their reports share one
schema — so they can be compared finding by finding. This page documents
every known difference, kept current by an automated conformance harness
that compares tens of thousands of verdicts against reference reports on
every change.

**Philosophy:** the default packs mirror the hosted engine's verdicts
exactly wherever its behavior is observable and self-consistent. Where the
hosted engine contradicts itself, we keep the honest verdict and document
the deviation here and in [open-questions.md](open-questions.md).

## Check corpus

- **Hosted-only checks** (largest raw difference): several per-rule checks
  are not yet implemented offline — App-ID specificity on allow rules,
  Server Response Inspection, session logging, the four GenAI application
  checks, and AIPD-EDLs-in-deny-rules. The GenAI/App-ID family requires
  predefined application-filter content data that doesn't ship yet. When
  run through `api-scan`, these appear as `pan-api-<id>` findings, so
  nothing the hosted engine reports is dropped.
- **Offline-only checks**: per-rule profile coverage (`rule-profiles-attached`,
  with profile-group resolution), session-end logging per rule,
  license-expiry with supersession awareness, license-aware Advanced IP
  Defense semantics, post-quantum crypto rounds, and others. The hosted
  engine's current registry carries no IDs for these.

## Verdict vocabulary

Both engines' raw verdicts are pass/fail. Offline (and the `api-scan`
converter) adds two refinements:

- `n/a` — allow-scoped checks on non-allow rules are out of scope.
- `note` — real observations deliberately not counted as failures: failing
  settings on *disabled* rules, predefined read-only objects, unlicensed
  Advanced IP Defense, and expired licenses superseded by an active
  equivalent entitlement.

## Panorama evaluation

Both engines evaluate device-scope checks per template-stack and rulebase
checks per device group. Verified differences:

| Area | Hosted engine | open-pan-bpa | Why we differ |
|---|---|---|---|
| Admin external auth per stack | Fails stacks regardless of pushed admin accounts | Evaluates the stack's composed `mgt-config` accounts | The hosted stack evaluation ignores accounts, contradicting its own firewall behavior |
| HA hardening on non-HA stacks | Fails HA checks on stacks with no HA config | HA checks apply only where HA is enabled | Matches the hosted engine's own firewall behavior |
| Template variables | Resolved per stack | Read as literals | Not yet implemented; a stack configuring values via `$variables` may differ on a handful of findings |
| Effective rulebases | Device-group ancestors included | Same (ancestors + shared) | — |
| Profile adoption via groups | Group members resolved | Same | — |

## Registry drift

The hosted engine's check registry changes server-side without notice.
Observed and tracked instances: default-rule logging flipped from
fail-everyone to correct evaluation (2026-08); explicit `default` antivirus
decoder actions flipped from pass to fail (2026-08, adoption pending fresh
references); check IDs and titles renumber between registries — which is
why check identity here is a stable slug and IDs are cross-references only.

## Where each is authoritative

- The hosted engine is authoritative for *its own* verdicts — `api-scan`
  reports them faithfully (with the vocabulary refinements above, which
  `--no-corrections` disables).
- The offline engine is deterministic and versioned: the same binary and
  packs produce the same report forever, air-gapped.
- Running both against the same tech support file and comparing is the
  strongest audit: the shared schema makes every difference visible, and
  this page should explain each one you find. A difference NOT explained
  here is a bug — please report it.
