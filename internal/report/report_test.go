package report

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gitupcourt/open-pan-bpa/internal/engine"
)

func testReport() *engine.Report {
	return &engine.Report{
		SchemaVersion: engine.SchemaVersion,
		ToolVersion:   "test",
		Hostname:      "unit-fw",
		GeneratedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Summary:       engine.Summary{Checks: 1, Objects: 2, Pass: 1, Fail: 1},
		Findings: []engine.Finding{
			{
				Slug: "a-check", Title: "A check", Severity: engine.Critical,
				Verdict: engine.Fail,
				// Hostile message: must not be able to terminate the
				// embedding <script> element.
				Message:    "bad value </script><script>alert(1)</script>",
				Object:     engine.ObjectRef{Feature: "security_rule", Name: "r1", Location: "vsys1"},
				References: []string{"https://example.invalid/doc"},
			},
			{
				Slug: "a-check", Title: "A check", Severity: engine.Critical,
				Verdict: engine.Pass,
				Object:  engine.ObjectRef{Feature: "security_rule", Name: "r2", Location: "dg-one"},
			},
			{
				Slug: "skipped", Title: "Not applicable", Severity: engine.High,
				Verdict: engine.NotApplicable,
				Object:  engine.ObjectRef{Feature: "security_rule", Name: "r3", Location: "vsys1"},
			},
		},
	}
}

var payloadRe = regexp.MustCompile(`(?s)<script id="data" type="application/json">(.*?)</script>`)

func TestWriteHTMLPayload(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, testReport()); err != nil {
		t.Fatal(err)
	}
	html := buf.String()

	m := payloadRe.FindStringSubmatch(html)
	if m == nil {
		t.Fatal("no embedded data payload found")
	}
	var p htmlPayload
	if err := json.Unmarshal([]byte(m[1]), &p); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if len(p.Checks) != 1 || p.Checks[0].Slug != "a-check" {
		t.Fatalf("checks = %+v, want single a-check", p.Checks)
	}
	if p.Checks[0].Pass != 1 || p.Checks[0].Fail != 1 {
		t.Fatalf("counts = %+v", p.Checks[0])
	}
	// n/a findings are excluded; the two real findings remain.
	if len(p.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(p.Findings))
	}
	if len(p.Locations) != 2 {
		t.Fatalf("locations = %v, want 2 entries", p.Locations)
	}
	// The hostile message survives round-trip intact…
	var msgs []string
	for _, f := range p.Findings {
		msgs = append(msgs, f[6].(string))
	}
	joined := strings.Join(msgs, " ")
	if !strings.Contains(joined, "alert(1)") {
		t.Fatal("message content lost in encoding")
	}
	// …but the payload region contains no literal script terminator beyond
	// the wrapper's own, so it cannot break out of the data element.
	if strings.Contains(m[1], "</script") {
		t.Fatal("unescaped </script inside embedded payload")
	}
}
