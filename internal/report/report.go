// Package report renders an engine.Report as JSON, CSV, and self-contained
// HTML. No output format references external assets — reports must render on
// an air-gapped workstation.
package report

import (
	_ "embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"

	"github.com/gitupcourt/open-pan-bpa/internal/engine"
)

// WriteJSON emits the canonical machine-readable report.
func WriteJSON(w io.Writer, rep *engine.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// WriteCSV emits one row per finding.
func WriteCSV(w io.Writer, rep *engine.Report) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"slug", "title", "severity", "verdict", "section", "feature", "object", "location", "message", "references"}); err != nil {
		return err
	}
	for _, f := range rep.Findings {
		if err := cw.Write([]string{
			f.Slug, f.Title, string(f.Severity), string(f.Verdict),
			f.Object.Section, f.Object.Feature, f.Object.Name, f.Object.Location, f.Message,
			strings.Join(f.References, " "),
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

//go:embed template.html
var htmlTemplate string

type htmlData struct {
	Rep     *engine.Report
	Payload template.JS // findings dataset, embedded as JSON
}

// htmlCheck is one check's summary row in the embedded dataset.
type htmlCheck struct {
	Slug       string   `json:"slug"`
	Title      string   `json:"title"`
	Severity   int      `json:"sev"`
	Section    string   `json:"sec"` // policies | objects | network | device
	References []string `json:"refs,omitempty"`
	Pass       int      `json:"pass"`
	Fail       int      `json:"fail"`
	Notes      int      `json:"notes"`
}

// htmlPayload is the client-rendered dataset. Findings are compact tuples
// referencing the checks and locations tables by index:
//
//	[checkIdx, verdictCode, severityCode, locationIdx, feature, name, message]
//
// verdictCode: 0 fail, 1 note, 2 pass. severityCode: 0 critical … 3
// informational. The findings table in the HTML is rendered on demand from
// this data — a Panorama fleet report holds tens of thousands of findings,
// and materializing them all as DOM up front made reports of that size
// effectively unusable.
type htmlPayload struct {
	Checks    []htmlCheck `json:"checks"`
	Locations []string    `json:"locations"`
	Findings  [][7]any    `json:"findings"`
}

var severityCode = map[engine.Severity]int{
	engine.Critical: 0, engine.High: 1, engine.Warning: 2, engine.Informational: 3,
}

var verdictCode = map[engine.Verdict]int{
	engine.Fail: 0, engine.Note: 1, engine.Pass: 2,
}

// WriteHTML emits a self-contained single-file report.
func WriteHTML(w io.Writer, rep *engine.Report) error {
	t, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parsing embedded template: %w", err)
	}

	var p htmlPayload
	checkIdx := map[string]int{}
	locIdx := map[string]int{}
	for _, f := range rep.Findings {
		if f.Verdict == engine.NotApplicable {
			continue
		}
		ci, ok := checkIdx[f.Slug]
		if !ok {
			ci = len(p.Checks)
			checkIdx[f.Slug] = ci
			p.Checks = append(p.Checks, htmlCheck{
				Slug: f.Slug, Title: f.Title,
				Severity: severityCode[f.Severity], Section: f.Object.Section,
				References: f.References,
			})
		}
		li, ok := locIdx[f.Object.Location]
		if !ok {
			li = len(p.Locations)
			locIdx[f.Object.Location] = li
			p.Locations = append(p.Locations, f.Object.Location)
		}
		switch f.Verdict {
		case engine.Pass:
			p.Checks[ci].Pass++
		case engine.Fail:
			p.Checks[ci].Fail++
		case engine.Note:
			p.Checks[ci].Notes++
		}
		p.Findings = append(p.Findings, [7]any{
			ci, verdictCode[f.Verdict], severityCode[f.Severity], li,
			f.Object.Feature, f.Object.Name, f.Message,
		})
	}

	// Stable check order for the by-check table; finding tuples keep their
	// index-based references valid because we sort an index list client-side,
	// never the checks array itself.
	orderedIdx := make([]int, len(p.Checks))
	for i := range orderedIdx {
		orderedIdx[i] = i
	}
	sort.SliceStable(orderedIdx, func(a, b int) bool {
		return p.Checks[orderedIdx[a]].Slug < p.Checks[orderedIdx[b]].Slug
	})
	remap := make([]int, len(p.Checks))
	ordered := make([]htmlCheck, len(p.Checks))
	for newI, oldI := range orderedIdx {
		remap[oldI] = newI
		ordered[newI] = p.Checks[oldI]
	}
	p.Checks = ordered
	for i := range p.Findings {
		p.Findings[i][0] = remap[p.Findings[i][0].(int)]
	}

	// json.Marshal escapes <, >, & to < etc., so the payload can never
	// terminate the surrounding <script> element early.
	raw, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("encoding findings payload: %w", err)
	}
	// Belt-and-braces: no raw "</" survives even if escaping behavior changes.
	safe := strings.ReplaceAll(string(raw), "</", "<\\/")

	return t.Execute(w, htmlData{Rep: rep, Payload: template.JS(safe)})
}
