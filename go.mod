module github.com/gitupcourt/open-pan-bpa

go 1.24

// Minimum toolchain, not just language version: stdlib fixes ship with the
// toolchain, and this binary decodes untrusted XML with it (GO-2026-6088,
// GO-2026-6091 — both fixed in 1.26.6). CI + releases resolve this via
// GOTOOLCHAIN=auto; keep it at a patch level govulncheck reports clean.
toolchain go1.26.6

require gopkg.in/yaml.v3 v3.0.1
