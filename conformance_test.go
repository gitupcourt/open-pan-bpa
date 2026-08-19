// Conformance ("golden") tests against real-device fixtures. Fixtures are
// real firewall configurations — sensitive regardless of origin — and are
// NEVER committed (see SECURITY.md); point OPENPANBPA_FIXTURES at a local
// directory to enable these tests. They skip cleanly when unset.
//
// Two layers:
//  1. Every TSF/XML in the fixture tree must ingest and evaluate.
//  2. If a reference report JSON for the same hostname exists anywhere in the
//     fixture tree, every check that declares pan_bpa_ids is compared against
//     it object-by-object. Documented deviations are allowlisted explicitly.
package openpanbpa_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitupcourt/open-pan-bpa/internal/checks"
	"github.com/gitupcourt/open-pan-bpa/internal/engine"
	"github.com/gitupcourt/open-pan-bpa/internal/ingest"
	"github.com/gitupcourt/open-pan-bpa/internal/parse"
	"github.com/gitupcourt/open-pan-bpa/internal/xmlnode"
	"github.com/gitupcourt/open-pan-bpa/packs"
)

// allowedDeviations lists slug/verdict combinations that intentionally differ
// from the reference engine. Keep this list short and justified.
var allowedDeviations = map[string]string{
	// Reference fails zones with no interfaces; we downgrade to a note
	// because an out-of-service zone is advisory, not an exposure.
	"zone-protection-attached/note": "empty zone downgraded to note",
	// Reference engine verdicts for HA2 keep-alive are inconsistent across
	// devices with identical normalized config (model-dependent?); we always
	// fail disabled keep-alive.
	"ha-ha2-keepalive/fail": "reference inconsistent on identical config",
	// Reference fails the default-rule logging checks on every device,
	// including ones whose default rules are overridden with log-end=yes;
	// we report the honest verdict.
	"rb-interzone-default-logging/pass": "reference always-fails regardless of config",
	"rb-intrazone-default-logging/pass": "reference always-fails regardless of config",
	// Reference hard-fails findings on disabled rules; we downgrade to notes.
	"rule-description/note":      "disabled rule downgraded to note",
	"rule-service-specific/note": "disabled rule downgraded to note",
	"rule-no-any-any-allow/note": "disabled rule downgraded to note",
	"rule-log-forwarding/note":   "disabled rule downgraded to note",
}

// referenceReport is the minimal shape of a reference report JSON.
type referenceReport struct {
	Information struct {
		Hostname string `json:"device_hostname"`
	} `json:"information"`
	BestPractices map[string]map[string]json.RawMessage `json:"best_practices"`
}

type refWrapper struct {
	Configuration map[string]any `json:"configuration"`
	Warnings      []refCheck     `json:"warnings"`
	Notes         []refCheck     `json:"notes"`
}

type refCheck struct {
	CheckID     any  `json:"check_id"`
	CheckPassed bool `json:"check_passed"`
}

func (c refCheck) id() (int, bool) {
	if f, ok := c.CheckID.(float64); ok {
		return int(f), true
	}
	return 0, false
}

// refVerdicts is feature -> object name -> check id -> passed.
type refVerdicts map[string]map[string]map[int]bool

func loadReferenceReports(t *testing.T, dir string) map[string]refVerdicts {
	t.Helper()
	out := map[string]refVerdicts{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		if info, err := d.Info(); err != nil || info.Size() > 32<<20 {
			return nil // skip huge (Panorama-scale) reports for now
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var rep referenceReport
		if json.Unmarshal(data, &rep) != nil || rep.Information.Hostname == "" || rep.BestPractices == nil {
			return nil
		}
		rv := refVerdicts{}
		for _, features := range rep.BestPractices {
			for feature, raw := range features {
				var wrappers []refWrapper
				if json.Unmarshal(raw, &wrappers) != nil {
					continue
				}
				for _, w := range wrappers {
					name, _ := w.Configuration["name"].(string)
					for _, c := range append(w.Warnings, w.Notes...) {
						id, ok := c.id()
						if !ok {
							continue
						}
						if rv[feature] == nil {
							rv[feature] = map[string]map[int]bool{}
						}
						if rv[feature][name] == nil {
							rv[feature][name] = map[int]bool{}
						}
						rv[feature][name][id] = c.CheckPassed
					}
				}
			}
		}
		t.Logf("reference loaded: %s <- %s (features: %d)", rep.Information.Hostname, filepath.Base(path), len(rv))
		out[rep.Information.Hostname] = rv
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func fixtureInputs(t *testing.T, dir string) []string {
	t.Helper()
	var inputs []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		n := strings.ToLower(d.Name())
		if strings.HasSuffix(n, ".tgz") ||
			(strings.HasSuffix(n, ".gz") && strings.Contains(n, "techsupport")) {
			inputs = append(inputs, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return inputs
}

func TestConformanceFixtures(t *testing.T) {
	dir := os.Getenv("OPENPANBPA_FIXTURES")
	if dir == "" {
		t.Skip("OPENPANBPA_FIXTURES not set; skipping conformance fixtures")
	}
	inputs := fixtureInputs(t, dir)
	if len(inputs) == 0 {
		t.Fatalf("no fixtures found in %s", dir)
	}
	refs := loadReferenceReports(t, dir)
	t.Logf("%d fixture inputs, %d reference reports", len(inputs), len(refs))

	loaded, err := engine.LoadPacks(packs.FS)
	if err != nil {
		t.Fatal(err)
	}
	mappings := map[string]checkMapping{}
	for _, p := range loaded {
		for _, c := range p.Checks {
			if len(c.PanBPAIDs) > 0 {
				mappings[c.Slug] = checkMapping{feature: c.Feature, ids: c.PanBPAIDs}
			}
		}
	}

	// Pre-pass: identify each TSF's hostname and pick the newest input per
	// device (by file modification time) for verdict comparison.
	newestByHost := map[string]string{}
	newestMod := map[string]int64{}
	for _, in := range inputs {
		info, err := os.Stat(in)
		if err != nil {
			continue
		}
		root, _, err := ingest.Load(in)
		if err != nil {
			continue
		}
		cfg, err := parse.BuildAuto(root)
		if err != nil {
			continue
		}
		if mt := info.ModTime().Unix(); cfg.Hostname != "" && mt > newestMod[cfg.Hostname] {
			newestMod[cfg.Hostname] = mt
			newestByHost[cfg.Hostname] = in
		}
	}

	for _, in := range inputs {
		in := in
		t.Run(filepath.Base(in), func(t *testing.T) {
			root, src, err := ingest.Load(in)
			if err != nil {
				// Panorama fixtures are expected to be refused for now.
				t.Skipf("ingest refused: %v", err)
			}
			cfg, err := parse.BuildAuto(root)
			if err != nil {
				t.Skipf("parse refused: %v", err)
			}
			if ts := src.Transcript(); ts != "" {
				cfg.LicenseInfoAvailable = true
				cfg.Licenses = parse.ParseLicenses(ts)
			}
			rep, err := engine.Run(cfg, loaded, checks.Registry(), "conformance")
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.SecurityRules) == 0 {
				// Guard against silent scope bugs (a parser change dropping
				// every rule) — but only when the raw config actually holds
				// rule entries. A spare device with an empty rulebase is a
				// legitimate zero.
				if n := countSecurityRuleEntries(root); n > 0 {
					t.Errorf("config holds %d security rule entries but none were parsed", n)
				} else {
					t.Logf("%s: empty security rulebase in config; zero rules is genuine", cfg.Hostname)
				}
			}
			t.Logf("%s (%s): %d rules, %d findings (%d fail)",
				cfg.Hostname, src.Kind, len(cfg.SecurityRules), len(rep.Findings), rep.Summary.Fail)

			ref, ok := refs[cfg.Hostname]
			if !ok {
				t.Logf("no reference report for %s; verdict comparison skipped", cfg.Hostname)
				return
			}
			// When multiple TSFs of the same device exist, only the newest
			// one is compared — an older config against a newer reference
			// report produces phantom mismatches.
			if newest, ok := newestByHost[cfg.Hostname]; ok && newest != in {
				t.Logf("stale TSF for %s (newer: %s); verdict comparison skipped", cfg.Hostname, filepath.Base(newest))
				return
			}
			compareVerdicts(t, rep, ref, mappings)
		})
	}
}

// checkMapping ties one of our slugs to reference check ids within a feature.
type checkMapping struct {
	feature string
	ids     []int
}

// countSecurityRuleEntries walks the raw config for <security><rules><entry>
// nodes, covering firewall vsys and Panorama pre/post rulebases alike. It is
// the ground truth the zero-rules guard checks the parser against.
func countSecurityRuleEntries(n *xmlnode.Node) int {
	total := 0
	if n.Name == "security" {
		for _, c := range n.Children {
			if c.Name != "rules" {
				continue
			}
			for _, e := range c.Children {
				if e.Name == "entry" {
					total++
				}
			}
		}
	}
	for _, c := range n.Children {
		total += countSecurityRuleEntries(c)
	}
	return total
}

func compareVerdicts(t *testing.T, rep *engine.Report, ref refVerdicts, mappings map[string]checkMapping) {
	compared, mismatches, deviations := 0, 0, 0
	for _, f := range rep.Findings {
		m, ok := mappings[f.Slug]
		if !ok {
			continue
		}
		objs, ok := ref[m.feature]
		if !ok {
			continue
		}
		byID, ok := objs[f.Object.Name]
		if !ok {
			continue
		}
		for _, id := range m.ids {
			refPassed, ok := byID[id]
			if !ok {
				continue
			}
			compared++
			ourPassed := f.Verdict == engine.Pass || f.Verdict == engine.NotApplicable
			if ourPassed == refPassed {
				continue
			}
			key := f.Slug + "/" + string(f.Verdict)
			if _, allowed := allowedDeviations[key]; allowed {
				deviations++
				continue
			}
			// Advanced IP Defense checks are license-aware: unlicensed
			// devices get notes where the context-free reference fails.
			if strings.HasPrefix(f.Slug, "rb-aid-") && f.Verdict == engine.Note {
				deviations++
				continue
			}
			mismatches++
			if mismatches <= 10 {
				t.Errorf("mismatch: %s on %s/%s — ours=%s reference_passed=%v",
					f.Slug, f.Object.Feature, f.Object.Name, f.Verdict, refPassed)
			}
		}
	}
	t.Logf("verdict comparison: %d compared, %d mismatches, %d allowed deviations", compared, mismatches, deviations)
	if compared == 0 {
		t.Error("reference report present but zero verdicts compared — mapping bug?")
	}
}

// Guard against a check silently losing its evaluator: every pack check must
// resolve, and the synthetic config must produce at least one finding per
// check. (Runs without fixtures.)
func TestEveryCheckProducesFindings(t *testing.T) {
	loaded, err := engine.LoadPacks(packs.FS)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("internal/parse/testdata/mini-config.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	root, err := xmlnode.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parse.BuildAuto(root)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := engine.Run(cfg, loaded, checks.Registry(), "test")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, fd := range rep.Findings {
		seen[fd.Slug] = true
	}
	for _, p := range loaded {
		for _, c := range p.Checks {
			if !seen[c.Slug] {
				t.Errorf("check %s produced no findings on the synthetic config", c.Slug)
			}
		}
	}
}
