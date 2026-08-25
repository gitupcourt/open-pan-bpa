// Pack lint: every check must be traceable to primary documentation. This is
// the enforcement behind the README's sourcing promise — a check without
// references or a rationale does not build. Unlike the conformance tests,
// this runs unconditionally (no fixtures required).
package openpanbpa_test

import (
	"strings"
	"testing"

	"github.com/gitupcourt/open-pan-bpa/internal/engine"
	"github.com/gitupcourt/open-pan-bpa/packs"
)

func TestEveryCheckCitesDocumentation(t *testing.T) {
	loaded, err := engine.LoadPacks(packs.FS)
	if err != nil {
		t.Fatal(err)
	}
	checks := 0
	for _, p := range loaded {
		for _, c := range p.Checks {
			checks++
			if len(c.References) == 0 {
				t.Errorf("%s/%s: no documentation references", p.Name, c.Slug)
			}
			for _, ref := range c.References {
				if !strings.HasPrefix(ref, "https://") {
					t.Errorf("%s/%s: reference %q is not an https URL", p.Name, c.Slug, ref)
				}
			}
			if strings.TrimSpace(c.Rationale) == "" {
				t.Errorf("%s/%s: no rationale", p.Name, c.Slug)
			}
		}
	}
	if checks == 0 {
		t.Fatal("no checks loaded from embedded packs")
	}
}
