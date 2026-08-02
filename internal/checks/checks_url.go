package checks

import (
	"sort"

	"github.com/gitupcourt/open-pan-bpa/internal/engine"
	"github.com/gitupcourt/open-pan-bpa/internal/model"
)

// URL category groups; independently derived from public best-practices
// documentation. Category names track the Advanced URL Filtering vocabulary.
var (
	urlMaliciousCats = []string{
		"command-and-control", "compromised-website", "grayware",
		"malware", "phishing", "ransomware", "scanning-activity",
	}
	urlLiabilityCats = []string{
		"abused-drugs", "adult", "copyright-infringement", "extremism",
		"gambling", "peer-to-peer", "questionable", "weapons",
	}
	urlRiskyCats = []string{
		"dynamic-dns", "encrypted-dns", "hacking", "insufficient-content",
		"newly-registered-domain", "not-resolved", "parked",
		"proxy-avoidance-and-anonymizers", "unknown", "scanning-activity",
	}
	// The credential-submission variant of the risky group predates the
	// encrypted-dns / scanning-activity additions (reference-verified: those
	// two are not required for credential blocking).
	urlCredRiskyCats = []string{
		"dynamic-dns", "hacking", "insufficient-content",
		"newly-registered-domain", "not-resolved", "parked",
		"proxy-avoidance-and-anonymizers", "unknown",
	}
	urlGenAICats = []string{
		"AI-code-assistant", "AI-conversational-assistant",
		"AI-data-and-workflow-optimizer", "AI-meeting-assistant",
		"AI-platform-service", "AI-writing-assistant",
	}
)

// urlRegistry returns URL Filtering evaluators.
func urlRegistry() engine.Registry {
	return engine.Registry{
		"uf_block_malicious":  ufListCovered(urlMaliciousCats, ufBlock, "known-malicious URL categories are not blocked"),
		"uf_block_liability":  ufListCovered(urlLiabilityCats, ufBlock, "liability-risk URL categories are not blocked"),
		"uf_block_risky":      ufListCovered(urlRiskyCats, ufBlock, "potentially malicious URL categories are not blocked"),
		"uf_cred_malicious":   ufListCovered(urlMaliciousCats, ufCredBlock, "credential submission is not blocked for known-malicious categories"),
		"uf_cred_liability":   ufListCovered(urlLiabilityCats, ufCredBlock, "credential submission is not blocked for liability-risk categories"),
		"uf_cred_risky":       ufListCovered(urlCredRiskyCats, ufCredBlock, "credential submission is not blocked for potentially malicious categories"),
		"uf_block_genai":      ufGenAI,
		"uf_log_container":    ufLogContainer,
		"uf_cred_mode":        ufCredMode,
		"uf_inline_ml":        ufInlineML,
		"uf_category_logging": ufCategoryLogging,
		"uf_cred_logging":     ufCredLogging,
	}
}

func ufObject(p model.URLFilteringProfile) engine.ObjectRef {
	return engine.ObjectRef{Section: "objects", Feature: "url_filtering_profile", Name: p.Name, Location: p.Location}
}

func ufBlock(p model.URLFilteringProfile) []string     { return p.Block }
func ufCredBlock(p model.URLFilteringProfile) []string { return p.CredBlock }

// ufListCovered: every category in want must appear in the selected list.
func ufListCovered(want []string, get func(model.URLFilteringProfile) []string, gap string) engine.Evaluator {
	return func(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
		var out []engine.Finding
		for _, p := range cfg.URLFilteringProfiles {
			f := engine.Finding{Object: ufObject(p), Verdict: engine.Pass}
			if missing := missingFrom(want, get(p)); len(missing) > 0 {
				f.Verdict = engine.Fail
				f.Message = "Some " + gap + "; unblocked categories in this group are reachable (and phishable) destinations."
				f.FailedFields = map[string]any{"missing": missing}
			}
			out = append(out, f)
		}
		return out
	}
}

// ufGenAI: the GenAI category set must be blocked for both site access and
// credential submission — sanctioned tools get re-allowed deliberately, not
// by category default.
func ufGenAI(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.URLFilteringProfiles {
		f := engine.Finding{Object: ufObject(p), Verdict: engine.Pass}
		problems := map[string]any{}
		if missing := missingFrom(urlGenAICats, p.Block); len(missing) > 0 {
			problems["site_access_missing"] = missing
		}
		if missing := missingFrom(urlGenAICats, p.CredBlock); len(missing) > 0 {
			problems["credential_submission_missing"] = missing
		}
		if len(problems) > 0 {
			f.Verdict = engine.Fail
			f.Message = "Generative AI categories are not fully blocked; allow only sanctioned AI tools via explicit policy, not by leaving the category open."
			f.FailedFields = problems
		}
		out = append(out, f)
	}
	return out
}

func ufLogContainer(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.URLFilteringProfiles {
		f := engine.Finding{Object: ufObject(p), Verdict: engine.Pass}
		if p.LogContainerOnly {
			f.Verdict = engine.Fail
			f.Message = "Log Container Page Only is enabled (the default); embedded-content URLs go unlogged, hiding the requests that matter in an investigation."
			f.FailedFields = map[string]any{"log-container-page-only": "yes"}
		}
		out = append(out, f)
	}
	return out
}

func ufCredMode(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.URLFilteringProfiles {
		f := engine.Finding{Object: ufObject(p), Verdict: engine.Pass}
		if p.CredMode != "domain-credentials" {
			mode := p.CredMode
			if mode == "" {
				mode = "disabled"
			}
			f.Verdict = engine.Fail
			f.Message = "Credential detection should use the Domain Credential Filter, which recognizes actual corporate credentials rather than any username-shaped input."
			f.FailedFields = map[string]any{"credential-enforcement.mode": mode}
		}
		out = append(out, f)
	}
	return out
}

func ufInlineML(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.URLFilteringProfiles {
		f := engine.Finding{Object: ufObject(p), Verdict: engine.Pass}
		problems := map[string]any{}
		if !p.CloudInlineCat {
			problems["cloud-inline-cat"] = "no"
		}
		for name, action := range p.MlavEngines {
			if action != "block" {
				problems["model:"+name] = action
			}
		}
		if len(problems) > 0 {
			f.Verdict = engine.Fail
			f.Message = "URL Filtering inline ML should be enabled with every model action set to block; detection-only ML flags phishing pages while users submit to them."
			f.FailedFields = problems
		}
		out = append(out, f)
	}
	return out
}

func ufCategoryLogging(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.URLFilteringProfiles {
		f := engine.Finding{Object: ufObject(p), Verdict: engine.Pass}
		if len(p.Allow) > 0 {
			f.Verdict = engine.Fail
			f.Message = "Categories set to allow generate no URL log at all; use alert instead so the traffic stays visible."
			f.FailedFields = map[string]any{"allow": p.Allow}
		}
		out = append(out, f)
	}
	return out
}

func ufCredLogging(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.URLFilteringProfiles {
		f := engine.Finding{Object: ufObject(p), Verdict: engine.Pass}
		if len(p.CredAllow) > 0 {
			f.Verdict = engine.Fail
			f.Message = "Credential submissions to categories set to allow are never logged; use alert as the minimum."
			f.FailedFields = map[string]any{"credential-enforcement.allow": p.CredAllow}
		}
		out = append(out, f)
	}
	return out
}

func missingFrom(want, have []string) []string {
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	var missing []string
	for _, w := range want {
		if !set[w] {
			missing = append(missing, w)
		}
	}
	sort.Strings(missing)
	return missing
}
