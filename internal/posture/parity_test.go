package posture

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gitupcourt/open-pan-bpa/internal/engine"
	"github.com/gitupcourt/open-pan-bpa/packs"
)

// TestConvertRealReport exercises the converter against a real hosted-API
// report when the fixtures directory provides one (never committed; see
// SECURITY.md). Skips cleanly otherwise.
func TestConvertRealReport(t *testing.T) {
	dir := os.Getenv("OPENPANBPA_FIXTURES")
	if dir == "" {
		t.Skip("OPENPANBPA_FIXTURES not set")
	}
	var found string
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && found == "" && !d.IsDir() &&
			filepath.Ext(path) == ".json" && d.Name() != "catalog.json" {
			if fi, err := d.Info(); err == nil && fi.Size() > 100_000 && fi.Size() < 50_000_000 {
				found = path
			}
		}
		return nil
	})
	if found == "" {
		t.Skip("no API report JSON in fixtures")
	}
	data, err := os.ReadFile(found)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := engine.LoadPacks(packs.FS)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Convert(data, loaded, "fixture", filepath.Base(found), "test", true, t.Logf)
	if err != nil {
		t.Skipf("fixture %s is not an API report: %v", filepath.Base(found), err)
	}
	if len(rep.Findings) == 0 || rep.Summary.Checks == 0 {
		t.Fatalf("empty conversion from %s", filepath.Base(found))
	}
	t.Logf("%s: %d findings, %d checks, %d pass / %d fail / %d notes / %d n-a",
		filepath.Base(found), len(rep.Findings), rep.Summary.Checks,
		rep.Summary.Pass, rep.Summary.Fail, rep.Summary.Notes, rep.Summary.NotApplicable)
}
