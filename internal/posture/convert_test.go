package posture

import (
	"strings"
	"testing"

	"github.com/gitupcourt/open-pan-bpa/internal/engine"
)

// Synthetic API report: no real device content. Exercises mapped and
// unmapped checks, the notes bucket, and every correction path.
const fixture = `{
  "information": {"last_updated_time": "2026-01-01 00:00:00"},
  "best_practices": {
    "policies": {
      "security_rule": [
        {
          "configuration": {"name": "allow-web", "location": "vsys1", "action": "allow", "rule_uuid": "u-1"},
          "warnings": [
            {"check_id": 5, "check_name": "Set the service field in security rules with an allow action", "check_type": "Warning", "check_message": "service is any", "check_passed": false, "failed_fields": {"service": "any"}},
            {"check_id": 999, "check_name": "Unmapped exotic check", "check_type": "Critical", "check_message": "exotic", "check_passed": false}
          ],
          "notes": [
            {"check_id": 7, "check_name": "Advisory thing", "check_type": "Note", "check_message": "advisory", "check_passed": false}
          ]
        },
        {
          "configuration": {"name": "deny-junk", "location": "vsys1", "action": "deny"},
          "warnings": [
            {"check_id": 5, "check_name": "Set the service field in security rules with an allow action", "check_type": "Warning", "check_message": "service is any", "check_passed": false}
          ],
          "notes": null
        },
        {
          "configuration": {"name": "old-rule", "location": "vsys1", "action": "allow", "disabled": "yes"},
          "warnings": [
            {"check_id": 12, "check_name": "Some rule check", "check_type": "Warning", "check_message": "bad", "check_passed": false}
          ],
          "notes": []
        }
      ]
    },
    "objects": {
      "antivirus_profile": [
        {
          "configuration": {"name": "default", "location": "predefined"},
          "warnings": [
            {"check_id": 30, "check_name": "AV thing", "check_type": "Warning", "check_message": "bad av", "check_passed": false},
            {"check_id": 31, "check_name": "AV pass thing", "check_type": "Warning", "check_message": "", "check_passed": true}
          ]
        }
      ]
    }
  }
}`

func testPacks() []engine.Pack {
	return []engine.Pack{{
		Name: "test",
		Checks: []engine.CheckMeta{
			{Slug: "rule-service-specific", Title: "Allow rules should not use service \"any\"",
				Severity: engine.Critical, Section: "policies", PanBPAIDs: []int{5},
				References: []string{"https://docs.paloaltonetworks.com/best-practices"}},
		},
	}}
}

func find(t *testing.T, rep *engine.Report, slug, object string) engine.Finding {
	t.Helper()
	for _, f := range rep.Findings {
		if f.Slug == slug && f.Object.Name == object {
			return f
		}
	}
	t.Fatalf("no finding %s on %s", slug, object)
	return engine.Finding{}
}

func TestConvert(t *testing.T) {
	rep, err := Convert([]byte(fixture), testPacks(), "unit-fw", "in.json", "test", true)
	if err != nil {
		t.Fatal(err)
	}

	// Mapped check adopts the catalog's identity, severity, and references.
	m := find(t, rep, "rule-service-specific", "allow-web")
	if m.Verdict != engine.Fail || m.Severity != engine.Critical || len(m.References) == 0 {
		t.Fatalf("mapped finding wrong: %+v", m)
	}
	if m.Object.UUID != "u-1" || m.Object.Section != "policies" {
		t.Fatalf("object attribution wrong: %+v", m.Object)
	}

	// Unmapped check passes through with the API's own text and check_type
	// severity.
	u := find(t, rep, "pan-api-999", "allow-web")
	if u.Title != "Unmapped exotic check" || u.Severity != engine.Critical {
		t.Fatalf("unmapped finding wrong: %+v", u)
	}

	// The API's notes bucket is advisory.
	if f := find(t, rep, "pan-api-7", "allow-web"); f.Verdict != engine.Note {
		t.Fatalf("notes-origin verdict = %s, want note", f.Verdict)
	}

	// Allow-only check on a deny rule is out of scope.
	if f := find(t, rep, "rule-service-specific", "deny-junk"); f.Verdict != engine.NotApplicable {
		t.Fatalf("allow-only on deny rule = %s, want n/a", f.Verdict)
	}

	// Disabled rule downgrades to note with the reason recorded.
	d := find(t, rep, "pan-api-12", "old-rule")
	if d.Verdict != engine.Note || !strings.Contains(d.Message, "disabled rule") {
		t.Fatalf("disabled-rule downgrade wrong: %+v", d)
	}

	// Predefined read-only object downgrades to note.
	p := find(t, rep, "pan-api-30", "default")
	if p.Verdict != engine.Note || !strings.Contains(p.Message, "predefined read-only") {
		t.Fatalf("predefined downgrade wrong: %+v", p)
	}

	// Passing checks stay clean.
	if f := find(t, rep, "pan-api-31", "default"); f.Verdict != engine.Pass || f.Message != "" {
		t.Fatalf("pass finding wrong: %+v", f)
	}

	s := rep.Summary
	if s.Pass != 1 || s.Fail != 2 || s.Notes != 3 || s.NotApplicable != 1 {
		t.Fatalf("summary wrong: %+v", s)
	}
	if rep.InputKind != "api" || rep.SchemaVersion != engine.SchemaVersion {
		t.Fatalf("envelope wrong: kind=%s schema=%s", rep.InputKind, rep.SchemaVersion)
	}
}

func TestConvertNoCorrections(t *testing.T) {
	rep, err := Convert([]byte(fixture), testPacks(), "unit-fw", "in.json", "test", false)
	if err != nil {
		t.Fatal(err)
	}
	if f := find(t, rep, "rule-service-specific", "deny-junk"); f.Verdict != engine.Fail {
		t.Fatalf("without corrections, deny-rule verdict = %s, want fail", f.Verdict)
	}
	if f := find(t, rep, "pan-api-12", "old-rule"); f.Verdict != engine.Fail {
		t.Fatalf("without corrections, disabled-rule verdict = %s, want fail", f.Verdict)
	}
}
