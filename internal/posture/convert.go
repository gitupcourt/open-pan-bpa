package posture

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gitupcourt/open-pan-bpa/internal/engine"
)

// Convert maps a hosted-API report JSON into the engine's report schema,
// applying the engine's native verdict vocabulary: allow-scoped checks on
// non-allow rules become n/a, and failed checks on disabled rules or
// predefined read-only objects downgrade to note (matching the offline
// engine's semantics). Check identity maps to catalog slugs through
// pan_bpa_ids; unmapped checks pass through as pan-api-<id> with the API's
// own text, so nothing is dropped.
func Convert(apiJSON []byte, packs []engine.Pack, hostname, inputPath, toolVersion string, corrections bool) (*engine.Report, error) {
	var api struct {
		BestPractices map[string]map[string]json.RawMessage `json:"best_practices"`
		Information   struct {
			LastUpdatedTime string `json:"last_updated_time"`
		} `json:"information"`
	}
	if err := json.Unmarshal(apiJSON, &api); err != nil {
		return nil, fmt.Errorf("parsing API report: %w", err)
	}
	if len(api.BestPractices) == 0 {
		return nil, fmt.Errorf("API report has no best_practices content")
	}

	byID := map[int]engine.CheckMeta{}
	for _, p := range packs {
		for _, c := range p.Checks {
			for _, id := range c.PanBPAIDs {
				if _, ok := byID[id]; !ok {
					byID[id] = c
				}
			}
		}
	}

	registry := api.Information.LastUpdatedTime
	if registry == "" {
		registry = "unknown"
	}
	rep := &engine.Report{
		SchemaVersion: engine.SchemaVersion,
		Tool:          "open-pan-bpa",
		ToolVersion:   toolVersion + " api-scan (api registry " + registry + ")",
		GeneratedAt:   time.Now().UTC(),
		Hostname:      hostname,
		InputPath:     inputPath,
		InputKind:     "api",
	}

	var mapped, unmapped int
	// Deterministic order: sections, then features, alphabetically.
	for _, section := range sortedKeys(api.BestPractices) {
		feats := api.BestPractices[section]
		for _, feature := range sortedKeys(feats) {
			var wrappers []apiWrapper
			// Feature values are wrapper lists; tolerate null and odd shapes.
			if err := json.Unmarshal(feats[feature], &wrappers); err != nil {
				continue
			}
			for _, w := range wrappers {
				obj := engine.ObjectRef{
					Section:  section,
					Feature:  feature,
					Name:     str(w.Configuration["name"]),
					Location: str(w.Configuration["location"]),
				}
				if u := str(w.Configuration["rule_uuid"]); u != "" {
					obj.UUID = u
				} else if u := str(w.Configuration["uuid"]); u != "" {
					obj.UUID = u
				}
				for _, chk := range w.Warnings {
					f, m := convertCheck(chk, "warnings", obj, w.Configuration, feature, byID, corrections)
					rep.Findings = append(rep.Findings, f)
					mapped, unmapped = mapped+b2i(m), unmapped+b2i(!m)
				}
				for _, chk := range w.Notes {
					f, m := convertCheck(chk, "notes", obj, w.Configuration, feature, byID, corrections)
					rep.Findings = append(rep.Findings, f)
					mapped, unmapped = mapped+b2i(m), unmapped+b2i(!m)
				}
			}
		}
	}

	slugs := map[string]bool{}
	objects := map[engine.ObjectRef]bool{}
	rep.Summary.FailBySev = map[string]int{}
	for _, f := range rep.Findings {
		slugs[f.Slug] = true
		key := f.Object
		key.UUID = ""
		objects[key] = true
		switch f.Verdict {
		case engine.Pass:
			rep.Summary.Pass++
		case engine.Fail:
			rep.Summary.Fail++
			rep.Summary.FailBySev[string(f.Severity)]++
		case engine.Note:
			rep.Summary.Notes++
		default:
			rep.Summary.NotApplicable++
		}
	}
	rep.Summary.Checks = len(slugs)
	rep.Summary.Objects = len(objects)

	if rep.Summary.Checks == 0 {
		return nil, fmt.Errorf("API report contained no checks")
	}
	fmt.Printf("converted %d findings (%d slug-mapped, %d pan-api-* passthrough)\n", len(rep.Findings), mapped, unmapped)
	return rep, nil
}

type apiCheck struct {
	CheckID      *int           `json:"check_id"`
	CheckName    string         `json:"check_name"`
	CheckType    string         `json:"check_type"`
	CheckMessage string         `json:"check_message"`
	CheckPassed  bool           `json:"check_passed"`
	FailedFields map[string]any `json:"failed_fields"`
}

type apiWrapper struct {
	Configuration map[string]any `json:"configuration"`
	Warnings      []apiCheck     `json:"warnings"`
	Notes         []apiCheck     `json:"notes"`
}

// Rule-scoped checks that only apply to allow rules (current-registry IDs
// plus name fragments so the filter survives renumbering).
var allowOnlyCheckIDs = map[int]bool{5: true, 208: true, 351: true, 353: true, 354: true}

var allowOnlyNameFragments = []string{
	"with an allow action", "with the allow action", "action set to allow",
	"with an action of allow", "and the action is allow",
}

// Predefined read-only objects per feature (substring match on feature name).
var predefinedObjects = map[string]map[string]bool{
	"antivirus":     {"default": true, "strict": true},
	"anti_spyware":  {"default": true, "strict": true},
	"vulnerability": {"default": true, "strict": true},
	"file_blocking": {"basic file blocking": true, "strict file blocking": true},
	"wildfire":      {"default": true},
	"decryption":    {"default": true},
	"ike":           {"default": true, "Suite-B-GCM-128": true, "Suite-B-GCM-256": true},
	"ipsec":         {"default": true, "Suite-B-GCM-128": true, "Suite-B-GCM-256": true},
}

var severityByCheckType = map[string]engine.Severity{
	"critical":      engine.Critical,
	"warning":       engine.Warning,
	"note":          engine.Informational,
	"informational": engine.Informational,
}

func convertCheck(chk apiCheck, origin string, obj engine.ObjectRef, cfg map[string]any, feature string, byID map[int]engine.CheckMeta, corrections bool) (engine.Finding, bool) {
	verdict := engine.Fail
	if chk.CheckPassed {
		verdict = engine.Pass
	} else if origin == "notes" {
		verdict = engine.Note
	}
	noteReason := ""

	if corrections && !chk.CheckPassed {
		action := str(cfg["action"])
		switch {
		case isAllowOnly(chk.CheckID, chk.CheckName) && action != "" && action != "allow":
			verdict = engine.NotApplicable
		case strings.EqualFold(str(cfg["disabled"]), "yes") || strings.EqualFold(str(cfg["disabled"]), "true"):
			verdict = engine.Note
			noteReason = "disabled rule — remediate or delete"
		default:
			for key, names := range predefinedObjects {
				if strings.Contains(feature, key) && (names[obj.Name] || obj.Location == "predefined") {
					verdict = engine.Note
					noteReason = "predefined read-only — remediate via clone-and-attach"
					break
				}
			}
		}
	}

	f := engine.Finding{Verdict: verdict, Object: obj}
	var isMapped bool
	if chk.CheckID != nil {
		if meta, ok := byID[*chk.CheckID]; ok {
			f.Slug = meta.Slug
			f.Title = meta.Title
			f.Severity = meta.Severity
			f.References = meta.References
			isMapped = true
		}
	}
	if !isMapped {
		if chk.CheckID != nil {
			f.Slug = fmt.Sprintf("pan-api-%d", *chk.CheckID)
		} else {
			f.Slug = "pan-api-" + slugify(chk.CheckName)
		}
		f.Title = chk.CheckName
		if f.Title == "" {
			f.Title = f.Slug
		}
		sev, ok := severityByCheckType[strings.ToLower(chk.CheckType)]
		if !ok {
			sev = engine.Informational
		}
		f.Severity = sev
	}
	if verdict != engine.Pass {
		msg := chk.CheckMessage
		if noteReason != "" {
			if msg != "" {
				msg += " [" + noteReason + "]"
			} else {
				msg = noteReason
			}
		}
		f.Message = msg
		if len(chk.FailedFields) > 0 {
			f.FailedFields = chk.FailedFields
		}
	}
	return f, isMapped
}

func isAllowOnly(id *int, name string) bool {
	if id != nil && allowOnlyCheckIDs[*id] {
		return true
	}
	n := normTitle(name)
	if strings.Contains(n, "not allow") {
		return false
	}
	for _, frag := range allowOnlyNameFragments {
		if strings.Contains(n, frag) {
			return true
		}
	}
	return false
}

func normTitle(s string) string {
	s = strings.ToLower(s)
	s = strings.Map(func(r rune) rune {
		switch r {
		case '"', '\'', '‘', '’', '“', '”', '.', ',', ':', ';', '!', '?', '(', ')', '[', ']':
			return -1
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

func slugify(s string) string {
	s = normTitle(s)
	if len(s) > 40 {
		s = s[:40]
	}
	return strings.ReplaceAll(strings.TrimSpace(s), " ", "-")
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func sortedKeys[M ~map[string]V, V any](m M) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
