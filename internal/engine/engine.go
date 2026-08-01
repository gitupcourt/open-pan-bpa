// Package engine defines check metadata, verdicts, findings, and the runner
// that evaluates loaded check packs against a normalized configuration.
package engine

import (
	"fmt"
	"io/fs"
	"sort"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/gitupcourt/open-pan-bpa/internal/model"
)

// Verdict is the outcome of one check against one object.
type Verdict string

const (
	Pass          Verdict = "pass"
	Fail          Verdict = "fail"
	Note          Verdict = "note" // advisory: real observation, not a hard fail
	NotApplicable Verdict = "n/a"  // check out of scope for this object
)

// Severity mirrors the vendor taxonomy.
type Severity string

const (
	Informational Severity = "informational"
	Warning       Severity = "warning"
	High          Severity = "high"
	Critical      Severity = "critical"
)

// ObjectRef identifies the config object a finding is about.
type ObjectRef struct {
	Section  string `json:"section"`  // device | network | policies | objects
	Feature  string `json:"feature"`  // e.g. security_rule, zone
	Name     string `json:"name"`     // object name ("" for device-scope)
	Location string `json:"location"` // vsys / shared
	UUID     string `json:"uuid,omitempty"`
}

// Finding is one check result for one object.
type Finding struct {
	Slug         string         `json:"slug"`
	Title        string         `json:"title"`
	Severity     Severity       `json:"severity"`
	Verdict      Verdict        `json:"verdict"`
	Message      string         `json:"message,omitempty"`
	FailedFields map[string]any `json:"failed_fields,omitempty"`
	Object       ObjectRef      `json:"object"`
	References   []string       `json:"references,omitempty"`
}

// CheckMeta is one check definition from a pack.
type CheckMeta struct {
	Slug        string         `yaml:"slug" json:"slug"`
	Title       string         `yaml:"title" json:"title"`
	Severity    Severity       `yaml:"severity" json:"severity"`
	Section     string         `yaml:"section" json:"section"`
	Feature     string         `yaml:"feature" json:"feature"`
	Evaluator   string         `yaml:"evaluator" json:"evaluator"`
	Rationale   string         `yaml:"rationale" json:"rationale,omitempty"`
	Remediation string         `yaml:"remediation" json:"remediation,omitempty"`
	References  []string       `yaml:"references" json:"references,omitempty"`
	PanBPAIDs   []int          `yaml:"pan_bpa_ids" json:"pan_bpa_ids,omitempty"` // cross-reference only; not identity
	Params      map[string]any `yaml:"params" json:"params,omitempty"`
}

// Pack is a named collection of check definitions.
type Pack struct {
	Name    string      `yaml:"pack"`
	Version string      `yaml:"version"`
	Checks  []CheckMeta `yaml:"checks"`
}

// Evaluator computes findings for every object a check applies to. Evaluators
// must return Pass findings for conforming objects (not just failures) so
// summaries and adoption metrics can be computed from findings alone.
type Evaluator func(cfg *model.Config, meta CheckMeta) []Finding

// Registry maps evaluator names (referenced from packs) to implementations.
type Registry map[string]Evaluator

// Report is the versioned output document.
type Report struct {
	SchemaVersion string    `json:"schema_version"`
	Tool          string    `json:"tool"`
	ToolVersion   string    `json:"tool_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	Hostname      string    `json:"hostname"`
	Vsys          []string  `json:"vsys"`
	InputPath     string    `json:"input_path"`
	InputKind     string    `json:"input_kind"`
	Summary       Summary   `json:"summary"`
	Findings      []Finding `json:"findings"`
}

// Summary aggregates verdict counts.
type Summary struct {
	Checks        int            `json:"checks"`
	Objects       int            `json:"objects_evaluated"`
	Pass          int            `json:"pass"`
	Fail          int            `json:"fail"`
	Notes         int            `json:"notes"`
	NotApplicable int            `json:"not_applicable"`
	FailBySev     map[string]int `json:"fail_by_severity"`
}

// SchemaVersion is the report contract version. Bump on breaking change; the
// Ops Console integration pins against this.
const SchemaVersion = "0.1.0"

// LoadPacks parses every *.yaml pack in fsys.
func LoadPacks(fsys fs.FS) ([]Pack, error) {
	var packs []Pack
	entries, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, err
	}
	sort.Strings(entries)
	for _, name := range entries {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		var p Pack
		if err := yaml.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("pack %s: %w", name, err)
		}
		packs = append(packs, p)
	}
	return packs, nil
}

// Run evaluates all checks in all packs against cfg.
func Run(cfg *model.Config, packs []Pack, reg Registry, toolVersion string) (*Report, error) {
	rep := &Report{
		SchemaVersion: SchemaVersion,
		Tool:          "open-pan-bpa",
		ToolVersion:   toolVersion,
		GeneratedAt:   time.Now().UTC(),
		Hostname:      cfg.Hostname,
		Vsys:          cfg.Vsys,
	}
	seen := map[string]bool{}
	for _, p := range packs {
		for _, c := range p.Checks {
			if seen[c.Slug] {
				return nil, fmt.Errorf("duplicate check slug %q", c.Slug)
			}
			seen[c.Slug] = true
			ev, ok := reg[c.Evaluator]
			if !ok {
				return nil, fmt.Errorf("check %s references unknown evaluator %q", c.Slug, c.Evaluator)
			}
			findings := ev(cfg, c)
			for i := range findings {
				findings[i].Slug = c.Slug
				findings[i].Title = c.Title
				findings[i].Severity = c.Severity
				if len(c.References) > 0 && findings[i].Verdict == Fail {
					findings[i].References = c.References
				}
			}
			rep.Findings = append(rep.Findings, findings...)
			rep.Summary.Checks++
		}
	}
	rep.Summary.FailBySev = map[string]int{}
	objects := map[ObjectRef]bool{}
	for _, f := range rep.Findings {
		objects[f.Object] = true
		switch f.Verdict {
		case Pass:
			rep.Summary.Pass++
		case Fail:
			rep.Summary.Fail++
			rep.Summary.FailBySev[string(f.Severity)]++
		case Note:
			rep.Summary.Notes++
		case NotApplicable:
			rep.Summary.NotApplicable++
		}
	}
	rep.Summary.Objects = len(objects)
	return rep, nil
}
