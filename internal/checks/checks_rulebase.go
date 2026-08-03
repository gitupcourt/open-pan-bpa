package checks

import (
	"fmt"
	"strings"

	"github.com/gitupcourt/open-pan-bpa/internal/engine"
	"github.com/gitupcourt/open-pan-bpa/internal/model"
)

// rulebaseRegistry: rulebase-wide (not per-rule) security policy checks.
func rulebaseRegistry() engine.Registry {
	return engine.Registry{
		"rb_default_rule_logging": rbDefaultRuleLogging,
		"rb_edl_block":            rbEDLBlock,
		"rb_quic_block":           rbQUICBlock,
		"rb_userid_source_zones":  rbUserIDSourceZones,
		"rb_profile_adoption":     rbProfileAdoption,
		"rb_decrypt_rule_profile": rbDecryptRuleProfile,
	}
}

func rbObject(feature string) engine.ObjectRef {
	return engine.ObjectRef{Section: "policies", Feature: feature}
}

// rbDefaultRuleLogging: the named default rule must be overridden with
// session-end logging. Param rule_name selects intrazone/interzone.
func rbDefaultRuleLogging(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	want, _ := meta.Params["rule_name"].(string)
	f := engine.Finding{Object: rbObject(meta.Feature), Verdict: engine.Pass}
	found := false
	for _, r := range cfg.DefaultRules {
		if r.Name != want {
			continue
		}
		found = true
		if !r.LogEnd {
			f.Verdict = engine.Fail
			f.Message = fmt.Sprintf("The %s rule does not log at session end; the traffic it silently handles is the traffic no explicit rule matched.", want)
			f.FailedFields = map[string]any{"log-end": "no"}
		}
	}
	if !found {
		f.Verdict = engine.Fail
		f.Message = fmt.Sprintf("The %s rule is not overridden, so it keeps the factory default of no logging.", want)
		f.FailedFields = map[string]any{want: "not overridden"}
	}
	return []engine.Finding{f}
}

// rbEDLBlock: a deny/drop rule must reference the named external dynamic
// list on the traffic side given by the direction param. EDL names come from
// the pack (versioned data — the predefined list grows with content).
func rbEDLBlock(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	names, _ := meta.Params["edl_names"].([]any)
	direction, _ := meta.Params["direction"].(string)
	f := engine.Finding{Object: rbObject(meta.Feature), Verdict: engine.Fail}

	var want []string
	for _, n := range names {
		if s, ok := n.(string); ok {
			want = append(want, s)
		}
	}
	for _, r := range cfg.SecurityRules {
		if r.Disabled || !isDeny(r.Action) {
			continue
		}
		side := r.Source
		if direction == "outbound" {
			side = r.Destination
		}
		if containsAny(side, want) {
			f.Verdict = engine.Pass
			break
		}
	}
	if f.Verdict == engine.Fail {
		f.Message = fmt.Sprintf("No enabled deny rule blocks %s traffic using %s; these lists are maintained for you and cost nothing to enforce.",
			direction, strings.Join(want, " or "))
		f.FailedFields = map[string]any{"expected_edl": want, "direction": direction}
	}
	return []engine.Finding{f}
}

// rbQUICBlock: QUIC must be denied so TLS stays decryptable. Reference
// evidence: the check is NOT gated on decryption actually being configured —
// devices without any decryption rule still fail it.
func rbQUICBlock(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	f := engine.Finding{Object: rbObject(meta.Feature), Verdict: engine.Pass}
	blocked := false
	for _, r := range cfg.SecurityRules {
		if r.Disabled || !isDeny(r.Action) {
			continue
		}
		for _, a := range r.Application {
			if a == "quic" {
				blocked = true
				break
			}
		}
		if blocked {
			break
		}
	}
	if !blocked {
		f.Verdict = engine.Fail
		f.Message = "QUIC is not blocked; browsers prefer it over TLS, and the forward proxy cannot decrypt it — inspection is bypassed by default."
		f.FailedFields = map[string]any{"quic": "not denied"}
	}
	return []engine.Finding{f}
}

// rbUserIDSourceZones: rules that match specific source users need User-ID
// enabled on their source zones.
func rbUserIDSourceZones(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	f := engine.Finding{Object: rbObject(meta.Feature), Verdict: engine.Pass}
	userIDZones := map[string]bool{}
	for _, z := range cfg.Zones {
		if z.EnableUserIdentification {
			userIDZones[z.Name] = true
		}
	}
	gaps := map[string]any{}
	for _, r := range cfg.SecurityRules {
		if r.Disabled || listIsAny(r.SourceUser) {
			continue
		}
		for _, zone := range r.From {
			if zone == "any" || userIDZones[zone] {
				continue
			}
			gaps[zone] = "User-ID disabled but referenced by user-based rule " + r.Name
		}
	}
	if len(gaps) > 0 {
		f.Verdict = engine.Fail
		f.Message = "Rules match specific source users from zones where User-ID is disabled; those rules cannot match as intended."
		f.FailedFields = gaps
	}
	return []engine.Finding{f}
}

// rbProfileAdoption: at least one enabled rule must use the profile kind
// named by the profile_kind param.
func rbProfileAdoption(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	kind, _ := meta.Params["profile_kind"].(string)
	groups := map[string]model.ProfileGroup{}
	for _, g := range cfg.ProfileGroups {
		groups[g.Name] = g
	}
	f := engine.Finding{Object: rbObject(meta.Feature), Verdict: engine.Fail}
	for _, r := range cfg.SecurityRules {
		if r.Disabled {
			continue
		}
		if r.Profiles[kind] != "" {
			f.Verdict = engine.Pass
			break
		}
		if g, ok := groups[r.ProfileGroup]; ok && g.Profiles[kind] != "" {
			f.Verdict = engine.Pass
			break
		}
	}
	if f.Verdict == engine.Fail {
		f.Message = fmt.Sprintf("No enabled security rule uses a %s profile; the subscription is licensed but unenforced.", kind)
		f.FailedFields = map[string]any{"profile_kind": kind}
	}
	return []engine.Finding{f}
}

func rbDecryptRuleProfile(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, d := range cfg.DecryptionRules {
		f := engine.Finding{
			Object:  engine.ObjectRef{Section: "policies", Feature: meta.Feature, Name: d.Name, Location: d.Location},
			Verdict: engine.Pass,
		}
		if d.Action == "decrypt" && d.Profile == "" {
			f.Verdict = engine.Fail
			f.Message = "The decryption rule has no decryption profile; protocol versions, cipher suites, and certificate failures go unchecked on decrypted sessions."
			f.FailedFields = map[string]any{"profile": ""}
		}
		if d.Disabled && f.Verdict == engine.Fail {
			f.Verdict = engine.Note
			f.Message = "Rule is disabled — remediate before re-enabling, or delete it. " + f.Message
		}
		out = append(out, f)
	}
	return out
}

func isDeny(action string) bool {
	return action == "deny" || action == "drop" || action == "reset-both" ||
		action == "reset-client" || action == "reset-server"
}

func containsAny(haystack, needles []string) bool {
	set := map[string]bool{}
	for _, h := range haystack {
		set[h] = true
	}
	for _, n := range needles {
		if set[n] {
			return true
		}
	}
	return false
}
