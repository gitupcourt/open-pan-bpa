package checks

import (
	"os"
	"testing"

	"github.com/gitupcourt/open-pan-bpa/internal/engine"
	"github.com/gitupcourt/open-pan-bpa/internal/model"
	"github.com/gitupcourt/open-pan-bpa/internal/parse"
	"github.com/gitupcourt/open-pan-bpa/internal/xmlnode"
	"github.com/gitupcourt/open-pan-bpa/packs"
)

func miniConfig(t *testing.T) *model.Config {
	t.Helper()
	f, err := os.Open("../parse/testdata/mini-config.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	root, err := xmlnode.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parse.Build(root)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func runAll(t *testing.T) *engine.Report {
	t.Helper()
	loaded, err := engine.LoadPacks(packs.FS)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := engine.Run(miniConfig(t), loaded, Registry(), "test")
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// findingFor returns the finding for slug on the named object.
func findingFor(rep *engine.Report, slug, object string) *engine.Finding {
	for i, f := range rep.Findings {
		if f.Slug == slug && f.Object.Name == object {
			return &rep.Findings[i]
		}
	}
	return nil
}

func TestProfilesAttachedSemantics(t *testing.T) {
	rep := runAll(t)
	cases := []struct {
		object  string
		verdict engine.Verdict
	}{
		{"good-rule", engine.Pass},           // resolvable group with all core profiles
		{"naked-allow", engine.Fail},         // nothing attached
		{"thin-group-allow", engine.Fail},    // group attached but lacks core profiles
		{"individual-profiles", engine.Note}, // core profiles present but no group
		{"deny-rule", engine.NotApplicable},  // allow-only check skips deny
		{"disabled-bad-rule", engine.Note},   // disabled downgrades Fail → Note
	}
	for _, c := range cases {
		f := findingFor(rep, "rule-profiles-attached", c.object)
		if f == nil {
			t.Errorf("%s: no finding", c.object)
			continue
		}
		if f.Verdict != c.verdict {
			t.Errorf("%s: verdict = %s, want %s (msg: %s)", c.object, f.Verdict, c.verdict, f.Message)
		}
	}
}

func TestAllowOnlyChecksSkipDenyRules(t *testing.T) {
	rep := runAll(t)
	for _, slug := range []string{"rule-service-specific", "rule-no-any-any-allow"} {
		f := findingFor(rep, slug, "deny-rule")
		if f == nil || f.Verdict != engine.NotApplicable {
			t.Errorf("%s on deny-rule: got %+v, want n/a", slug, f)
		}
	}
}

func TestDeviceChecks(t *testing.T) {
	rep := runAll(t)

	ntp := findingFor(rep, "ntp-redundant", "")
	if ntp == nil || ntp.Verdict != engine.Fail {
		t.Fatalf("ntp-redundant: %+v", ntp)
	}
	if _, ok := ntp.FailedFields["secondary_ntp"]; !ok {
		t.Errorf("ntp failure should name the missing secondary, got %v", ntp.FailedFields)
	}

	pw := findingFor(rep, "password-complexity", "")
	if pw == nil || pw.Verdict != engine.Fail {
		t.Fatalf("password-complexity: %+v", pw)
	}
	// Enabled but numeric minimum is zero and length below param default.
	if _, ok := pw.FailedFields["minimum_numeric_letters"]; !ok {
		t.Errorf("password failure should name zeroed numeric minimum, got %v", pw.FailedFields)
	}

	pg := findingFor(rep, "profile-group-default-exists", "default")
	if pg == nil || pg.Verdict != engine.Fail {
		t.Errorf("profile-group-default-exists: %+v", pg)
	}
}

func TestZoneCheck(t *testing.T) {
	rep := runAll(t)
	if f := findingFor(rep, "zone-protection-attached", "trust"); f == nil || f.Verdict != engine.Pass {
		t.Errorf("trust: %+v", f)
	}
	if f := findingFor(rep, "zone-protection-attached", "untrust"); f == nil || f.Verdict != engine.Fail {
		t.Errorf("untrust: %+v", f)
	}
	if f := findingFor(rep, "zone-protection-attached", "spare"); f == nil || f.Verdict != engine.Note {
		t.Errorf("spare (no interfaces): %+v", f)
	}
}
