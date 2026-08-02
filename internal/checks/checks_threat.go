package checks

import (
	"fmt"

	"github.com/gitupcourt/open-pan-bpa/internal/engine"
	"github.com/gitupcourt/open-pan-bpa/internal/model"
)

// threatRegistry returns Anti-Spyware and Vulnerability Protection evaluators.
func threatRegistry() engine.Registry {
	return engine.Registry{
		"as_severity_rules":    asPerProfile(severityRulesFinding),
		"as_low_info_default":  asPerProfile(lowInfoDefaultFinding),
		"as_threat_exceptions": asPerProfile(threatExceptionsFinding),
		"as_dns_sinkhole":      asPerProfile(dnsSinkholeFinding),
		"as_dns_cloud":         asPerProfile(dnsCloudFinding),
		"as_inline_engines":    asPerProfile(inlineEnginesFinding),
		"as_inline_enabled":    asPerProfile(inlineEnabledFinding),
		"vp_severity_rules":    vpPerProfile(severityRulesFinding),
		"vp_low_info_default":  vpPerProfile(lowInfoDefaultFinding),
		"vp_threat_exceptions": vpPerProfile(threatExceptionsFinding),
		"vp_inline_engines":    vpPerProfile(inlineEnginesFinding),
		"vp_inline_enabled":    vpPerProfile(inlineEnabledFinding),
	}
}

// threatProfileView is the shared shape of AS/VP profiles for common checks.
type threatProfileView struct {
	object           engine.ObjectRef
	rules            []model.ThreatRule
	threatExceptions []string
	inlineEnabled    bool
	micaEngines      map[string]string
	dnsCategories    []model.DNSCategory
}

func asPerProfile(eval func(threatProfileView) engine.Finding) engine.Evaluator {
	return func(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
		var out []engine.Finding
		for _, p := range cfg.SpywareProfiles {
			out = append(out, eval(threatProfileView{
				object:           engine.ObjectRef{Section: "objects", Feature: "anti_spyware_profile", Name: p.Name, Location: p.Location},
				rules:            p.Rules,
				threatExceptions: p.ThreatExceptions,
				inlineEnabled:    p.CloudInlineAnalysis,
				micaEngines:      p.MicaEngines,
				dnsCategories:    p.DNSCategories,
			}))
		}
		return out
	}
}

func vpPerProfile(eval func(threatProfileView) engine.Finding) engine.Evaluator {
	return func(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
		var out []engine.Finding
		for _, p := range cfg.VulnerabilityProfiles {
			out = append(out, eval(threatProfileView{
				object:           engine.ObjectRef{Section: "objects", Feature: "vulnerability_protection_profile", Name: p.Name, Location: p.Location},
				rules:            p.Rules,
				threatExceptions: p.ThreatExceptions,
				inlineEnabled:    p.CloudInlineAnalysis,
				micaEngines:      p.MicaEngines,
			}))
		}
		return out
	}
}

// severityRulesFinding: critical, high, and medium must each be covered by a
// rule whose action blocks AND has packet capture enabled.
func severityRulesFinding(v threatProfileView) engine.Finding {
	f := engine.Finding{Object: v.object, Verdict: engine.Pass}
	uncovered := map[string]any{}
	for _, sev := range []string{"critical", "high", "medium"} {
		covered := false
		var closest string
		for _, r := range v.rules {
			if !hasSeverity(r, sev) {
				continue
			}
			if model.BlockingThreatActions[normalizeAction(r.Action)] && r.PacketCapture != "" && r.PacketCapture != "disable" {
				covered = true
				break
			}
			closest = fmt.Sprintf("rule %q action=%s packet_capture=%s", r.Name, orDefault(r.Action), orDefault(r.PacketCapture))
		}
		if !covered {
			if closest == "" {
				closest = "no rule covers this severity"
			}
			uncovered[sev] = closest
		}
	}
	if len(uncovered) > 0 {
		f.Verdict = engine.Fail
		f.Message = "Critical/high/medium threats need a rule with a blocking action (reset-both, drop, reset-client, reset-server, or block-ip) and packet capture enabled; see failed fields for the gap per severity."
		f.FailedFields = uncovered
	}
	return f
}

// lowInfoDefaultFinding: low and informational severities should be covered
// by rules using the default action.
func lowInfoDefaultFinding(v threatProfileView) engine.Finding {
	f := engine.Finding{Object: v.object, Verdict: engine.Pass}
	problems := map[string]any{}
	for _, sev := range []string{"low", "informational"} {
		ok := false
		var closest string
		for _, r := range v.rules {
			if !hasSeverity(r, sev) {
				continue
			}
			if normalizeAction(r.Action) == "default" {
				ok = true
				break
			}
			closest = fmt.Sprintf("rule %q action=%s", r.Name, orDefault(r.Action))
		}
		if !ok {
			if closest == "" {
				closest = "no rule covers this severity"
			}
			problems[sev] = closest
		}
	}
	if len(problems) > 0 {
		f.Verdict = engine.Fail
		f.Message = "Low and informational severities should be covered with the default signature action (visibility without blocking noise)."
		f.FailedFields = problems
	}
	return f
}

func threatExceptionsFinding(v threatProfileView) engine.Finding {
	f := engine.Finding{Object: v.object, Verdict: engine.Pass}
	if len(v.threatExceptions) > 0 {
		f.Verdict = engine.Fail
		f.Message = fmt.Sprintf("Profile carries %d threat exception(s); excepted signatures are never enforced. Resolve false positives via support, then remove the exception.", len(v.threatExceptions))
		f.FailedFields = map[string]any{"threat_exceptions": v.threatExceptions}
	}
	return f
}

// dnsSinkholeFinding: every configured DNS Security category (benign aside)
// must use the sinkhole action. Conformance evidence: packet-capture levels
// are NOT part of this check — profiles pass it with capture disabled — and
// an unconfigured profile inherits non-sinkhole content defaults, which
// fails.
func dnsSinkholeFinding(v threatProfileView) engine.Finding {
	f := engine.Finding{Object: v.object, Verdict: engine.Pass}
	problems := map[string]any{}
	configured := 0
	for _, c := range v.dnsCategories {
		if c.Name == "pan-dns-sec-benign" {
			continue
		}
		configured++
		if orDefault(c.Action) != "sinkhole" {
			problems[c.Name] = "action=" + orDefault(c.Action)
		}
	}
	if configured == 0 {
		problems["dns_security_categories"] = "not configured (categories inherit non-sinkhole content defaults)"
	}
	if len(problems) > 0 {
		f.Verdict = engine.Fail
		f.Message = "DNS Security categories should sinkhole malicious resolutions so the querying (compromised) host is identifiable in traffic logs."
		f.FailedFields = problems
	}
	return f
}

// dnsCloudFinding — "DNS cloud security" posture, semantics pinned by
// reference counterexamples: the command-and-control category must sinkhole
// with EXTENDED packet capture (single-packet fails); every other category
// (benign aside) must be sinkholed OR at least captured — default action with
// capture disabled means the lookup is neither blocked nor evidenced.
func dnsCloudFinding(v threatProfileView) engine.Finding {
	f := engine.Finding{Object: v.object, Verdict: engine.Pass}
	problems := map[string]any{}
	ccSeen := false
	for _, c := range v.dnsCategories {
		action, pcap := orDefault(c.Action), orDefault(c.PacketCapture)
		switch c.Name {
		case "pan-dns-sec-benign":
			continue
		case "pan-dns-sec-cc":
			ccSeen = true
			if action != "sinkhole" || c.PacketCapture != "extended-capture" {
				problems[c.Name] = fmt.Sprintf("action=%s, packet_capture=%s (needs sinkhole + extended-capture)", action, pcap)
			}
		default:
			if action != "sinkhole" && (pcap == "disable" || pcap == "default") {
				problems[c.Name] = fmt.Sprintf("action=%s, packet_capture=%s (neither blocked nor captured)", action, pcap)
			}
		}
	}
	if !ccSeen {
		problems["pan-dns-sec-cc"] = "not configured"
	}
	if len(problems) > 0 {
		f.Verdict = engine.Fail
		f.Message = "DNS cloud security posture: sinkhole C2 with extended capture; other categories must be sinkholed or at least captured."
		f.FailedFields = problems
	}
	return f
}

// inlineEnginesFinding: inline cloud analysis on, and every analysis engine
// set to a blocking action.
func inlineEnginesFinding(v threatProfileView) engine.Finding {
	f := engine.Finding{Object: v.object, Verdict: engine.Pass}
	problems := map[string]any{}
	if !v.inlineEnabled {
		problems["cloud_inline_analysis"] = "no"
	}
	for name, action := range v.micaEngines {
		if !model.BlockingThreatActions[normalizeAction(action)] {
			problems["engine:"+name] = action
		}
	}
	if len(problems) > 0 {
		f.Verdict = engine.Fail
		f.Message = "Inline Cloud Analysis should be enabled with every analysis engine set to a blocking action (drop or reset)."
		f.FailedFields = problems
	}
	return f
}

func inlineEnabledFinding(v threatProfileView) engine.Finding {
	f := engine.Finding{Object: v.object, Verdict: engine.Pass}
	if !v.inlineEnabled {
		f.Verdict = engine.Fail
		f.Message = "Inline Cloud Analysis is disabled; in-line ML verdicts are skipped for this profile."
		f.FailedFields = map[string]any{"cloud_inline_analysis": "no"}
	}
	return f
}

// --- helpers ---

func hasSeverity(r model.ThreatRule, sev string) bool {
	for _, s := range r.Severities {
		if s == sev || s == "any" {
			return true
		}
	}
	return false
}

// normalizeAction maps XML element action names (reset-both) and reference
// snake_case forms (reset_both) onto one vocabulary.
func normalizeAction(a string) string {
	switch a {
	case "reset_both":
		return "reset-both"
	case "reset_client":
		return "reset-client"
	case "reset_server":
		return "reset-server"
	case "block_ip":
		return "block-ip"
	case "":
		return "default"
	}
	return a
}

func orDefault(s string) string {
	if s == "" {
		return "default"
	}
	return s
}
