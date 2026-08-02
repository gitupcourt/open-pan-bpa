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
	if err := cw.Write([]string{"slug", "title", "severity", "verdict", "section", "feature", "object", "location", "message"}); err != nil {
		return err
	}
	for _, f := range rep.Findings {
		if err := cw.Write([]string{
			f.Slug, f.Title, string(f.Severity), string(f.Verdict),
			f.Object.Section, f.Object.Feature, f.Object.Name, f.Object.Location, f.Message,
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
	Rep      *engine.Report
	Findings []engine.Finding // fail, then note, then pass; n/a omitted
	BySlug   []slugSummary
}

type slugSummary struct {
	Slug, Title string
	Severity    engine.Severity
	Pass, Fail  int
	Notes       int
}

// WriteHTML emits a self-contained single-file report.
func WriteHTML(w io.Writer, rep *engine.Report) error {
	t, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parsing embedded template: %w", err)
	}
	d := htmlData{Rep: rep}
	bySlug := map[string]*slugSummary{}
	var order []string
	for _, f := range rep.Findings {
		s, ok := bySlug[f.Slug]
		if !ok {
			s = &slugSummary{Slug: f.Slug, Title: f.Title, Severity: f.Severity}
			bySlug[f.Slug] = s
			order = append(order, f.Slug)
		}
		switch f.Verdict {
		case engine.Pass:
			s.Pass++
		case engine.Fail:
			s.Fail++
		case engine.Note:
			s.Notes++
		}
		if f.Verdict != engine.NotApplicable {
			d.Findings = append(d.Findings, f)
		}
	}
	sort.Strings(order)
	for _, slug := range order {
		d.BySlug = append(d.BySlug, *bySlug[slug])
	}
	// Fail first (critical → informational), then notes, then passes.
	verdictRank := map[engine.Verdict]int{engine.Fail: 0, engine.Note: 1, engine.Pass: 2}
	sevRank := map[engine.Severity]int{engine.Critical: 0, engine.High: 1, engine.Warning: 2, engine.Informational: 3}
	sort.SliceStable(d.Findings, func(i, j int) bool {
		a, b := d.Findings[i], d.Findings[j]
		if verdictRank[a.Verdict] != verdictRank[b.Verdict] {
			return verdictRank[a.Verdict] < verdictRank[b.Verdict]
		}
		return sevRank[a.Severity] < sevRank[b.Severity]
	})
	return t.Execute(w, d)
}
