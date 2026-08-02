// Conformance ("golden") tests against real-device fixtures. Fixtures are
// real firewall configurations — sensitive regardless of origin — and are
// NEVER committed (see SECURITY.md); point
// OPENPANBPA_FIXTURES at a local directory containing tech support files
// (*.tgz / *.gz) to enable these tests. They skip cleanly when unset.
package openpanbpa_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gitupcourt/open-pan-bpa/internal/checks"
	"github.com/gitupcourt/open-pan-bpa/internal/engine"
	"github.com/gitupcourt/open-pan-bpa/internal/ingest"
	"github.com/gitupcourt/open-pan-bpa/internal/parse"
	"github.com/gitupcourt/open-pan-bpa/packs"
)

func TestConformanceFixtures(t *testing.T) {
	dir := os.Getenv("OPENPANBPA_FIXTURES")
	if dir == "" {
		t.Skip("OPENPANBPA_FIXTURES not set; skipping conformance fixtures")
	}
	var inputs []string
	for _, pat := range []string{"*.tgz", "*.gz", "*.xml"} {
		m, err := filepath.Glob(filepath.Join(dir, pat))
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, m...)
	}
	if len(inputs) == 0 {
		t.Fatalf("no fixtures found in %s", dir)
	}
	loaded, err := engine.LoadPacks(packs.FS)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range inputs {
		in := in
		t.Run(filepath.Base(in), func(t *testing.T) {
			root, src, err := ingest.Load(in)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := parse.Build(root)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Hostname == "" {
				t.Error("no hostname parsed")
			}
			if len(cfg.SecurityRules) == 0 {
				t.Error("no security rules parsed")
			}
			rep, err := engine.Run(cfg, loaded, checks.Registry(), "conformance")
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%s (%s, entry %s): %d rules, %d findings (%d fail)",
				cfg.Hostname, src.Kind, src.EntryName(),
				len(cfg.SecurityRules), len(rep.Findings), rep.Summary.Fail)
			// Phase 1 will pin expected-verdict baselines for these
			// fixtures so regressions in check logic are caught here.
		})
	}
}
