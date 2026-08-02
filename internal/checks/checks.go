// Package checks implements the seed evaluators referenced by the core check
// pack. Verdict semantics, applied engine-wide so findings stay actionable:
//
//   - Allow-only checks return NotApplicable for non-allow rules instead of
//     evaluating them.
//   - Findings on disabled rules downgrade Fail → Note ("remediate or delete").
//   - Every Fail names the actual failing fields.
package checks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gitupcourt/open-pan-bpa/internal/engine"
	"github.com/gitupcourt/open-pan-bpa/internal/model"
)

// Registry returns all built-in evaluators.
func Registry() engine.Registry {
	return engine.Registry{
		"rule_description":        ruleDescription,
		"rule_service_specific":   ruleServiceSpecific,
		"rule_no_any_any_allow":   ruleNoAnyAnyAllow,
		"rule_log_end":            ruleLogEnd,
		"rule_log_forwarding":     ruleLogForwarding,
		"rule_profiles_attached":  ruleProfilesAttached,
		"profile_group_default":   profileGroupDefault,
		"zone_protection_profile": zoneProtectionProfile,
		"ntp_redundant":           ntpRedundant,
		"password_complexity":     passwordComplexity,
	}
}

func ruleObject(r model.SecurityRule) engine.ObjectRef {
	return engine.ObjectRef{Section: "policies", Feature: "security_rule", Name: r.Name, Location: r.Location, UUID: r.UUID}
}

// downgradeDisabled converts a Fail on a disabled rule into a Note.
func downgradeDisabled(r model.SecurityRule, f engine.Finding) engine.Finding {
	if f.Verdict == engine.Fail && r.Disabled {
		f.Verdict = engine.Note
		f.Message = "Rule is disabled — remediate before re-enabling, or delete it. " + f.Message
	}
	return f
}

// forEachRule runs a per-rule evaluation, applying the disabled-rule downgrade.
func forEachRule(cfg *model.Config, eval func(model.SecurityRule) engine.Finding) []engine.Finding {
	out := make([]engine.Finding, 0, len(cfg.SecurityRules))
	for _, r := range cfg.SecurityRules {
		out = append(out, downgradeDisabled(r, eval(r)))
	}
	return out
}

// --- per-rule checks ---------------------------------------------------------

func ruleDescription(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	return forEachRule(cfg, func(r model.SecurityRule) engine.Finding {
		f := engine.Finding{Object: ruleObject(r), Verdict: engine.Pass}
		if strings.TrimSpace(r.Description) == "" {
			f.Verdict = engine.Fail
			f.Message = "Rule has no description; populate it so intent survives staff turnover and audits."
			f.FailedFields = map[string]any{"description": ""}
		}
		return f
	})
}

func ruleServiceSpecific(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	return forEachRule(cfg, func(r model.SecurityRule) engine.Finding {
		f := engine.Finding{Object: ruleObject(r)}
		if r.Action != "allow" {
			f.Verdict = engine.NotApplicable
			return f
		}
		for _, s := range r.Service {
			if s == "any" {
				f.Verdict = engine.Fail
				f.Message = "Allow rule permits any service port. Use application-default or an explicit service so App-ID evasion on arbitrary ports is contained."
				f.FailedFields = map[string]any{"service": r.Service}
				return f
			}
		}
		f.Verdict = engine.Pass
		return f
	})
}

func ruleNoAnyAnyAllow(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	return forEachRule(cfg, func(r model.SecurityRule) engine.Finding {
		f := engine.Finding{Object: ruleObject(r)}
		if r.Action != "allow" {
			f.Verdict = engine.NotApplicable
			return f
		}
		srcAny := listIsAny(r.Source) && listIsAny(r.From)
		dstAny := listIsAny(r.Destination) && listIsAny(r.To)
		if srcAny && dstAny {
			f.Verdict = engine.Fail
			f.Message = "Allow rule matches any source and any destination (zones and addresses). Scope at least one side."
			f.FailedFields = map[string]any{"source": r.Source, "destination": r.Destination, "from": r.From, "to": r.To}
			return f
		}
		f.Verdict = engine.Pass
		return f
	})
}

func ruleLogEnd(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	return forEachRule(cfg, func(r model.SecurityRule) engine.Finding {
		f := engine.Finding{Object: ruleObject(r), Verdict: engine.Pass}
		if !r.LogEnd {
			f.Verdict = engine.Fail
			f.Message = "Log at Session End is disabled; traffic matching this rule leaves no session log."
			f.FailedFields = map[string]any{"log_end": false}
		}
		return f
	})
}

func ruleLogForwarding(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	return forEachRule(cfg, func(r model.SecurityRule) engine.Finding {
		f := engine.Finding{Object: ruleObject(r), Verdict: engine.Pass}
		if r.LogSetting == "" {
			f.Verdict = engine.Fail
			f.Message = "No Log Forwarding profile attached; logs stay on-box and rotate away."
			f.FailedFields = map[string]any{"log_setting": ""}
		}
		return f
	})
}

// ruleProfilesAttached verifies allow rules actually carry the core threat
// profiles. A profile-group attachment only passes if the group resolves to
// them — a group without AV/AS/VP is still an uninspected allow rule.
func ruleProfilesAttached(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	groups := map[string]model.ProfileGroup{}
	for _, g := range cfg.ProfileGroups {
		groups[g.Name] = g
	}
	return forEachRule(cfg, func(r model.SecurityRule) engine.Finding {
		f := engine.Finding{Object: ruleObject(r)}
		if r.Action != "allow" {
			f.Verdict = engine.NotApplicable
			return f
		}

		// Resolve effective profiles: group members if a group is attached,
		// else the individually attached profiles.
		effective := map[string]string{}
		groupResolved := false
		if r.ProfileGroup != "" {
			if g, ok := groups[r.ProfileGroup]; ok {
				effective = g.Profiles
				groupResolved = true
			}
		} else {
			effective = r.Profiles
		}

		if r.ProfileGroup == "" && len(effective) == 0 {
			f.Verdict = engine.Fail
			f.Message = "Allow rule has no security profiles or profile group attached, so matching traffic receives no threat inspection at all."
			f.FailedFields = map[string]any{"profile_setting": nil}
			return f
		}

		var missing []string
		for _, kind := range model.CoreThreatProfiles {
			if effective[kind] == "" {
				missing = append(missing, kind)
			}
		}
		if r.ProfileGroup != "" && !groupResolved {
			f.Verdict = engine.Fail
			f.Message = fmt.Sprintf("Attached profile group %q was not found in this configuration scope; unable to confirm any threat inspection.", r.ProfileGroup)
			f.FailedFields = map[string]any{"profile_setting.group": r.ProfileGroup}
			return f
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			f.Verdict = engine.Fail
			f.FailedFields = map[string]any{"missing_core_profiles": missing, "attached": keys(effective)}
			if r.ProfileGroup != "" {
				f.Message = fmt.Sprintf("Attached profile group %q lacks core threat profiles: %s. Remediate the group itself and every rule using it is fixed at once.", r.ProfileGroup, strings.Join(missing, ", "))
				f.FailedFields["group"] = r.ProfileGroup
			} else {
				f.Message = "Allow rule is missing core threat profiles: " + strings.Join(missing, ", ") + "."
			}
			return f
		}
		if r.ProfileGroup == "" {
			f.Verdict = engine.Note
			f.Message = "Individual profiles attached; prefer a profile group (named 'default') so new rules auto-attach and coverage cannot drift."
			f.FailedFields = map[string]any{"attached": keys(effective)}
			return f
		}
		f.Verdict = engine.Pass
		return f
	})
}

// --- object / device checks --------------------------------------------------

func profileGroupDefault(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	obj := engine.ObjectRef{Section: "objects", Feature: "profile_group", Name: "default", Location: "shared"}
	for _, g := range cfg.ProfileGroups {
		if g.Name == "default" {
			return []engine.Finding{{Object: obj, Verdict: engine.Pass}}
		}
	}
	return []engine.Finding{{
		Object:  obj,
		Verdict: engine.Fail,
		Message: "No security profile group named 'default' exists. PAN-OS auto-attaches a group with this exact name to every new security rule — create a hardened one so new rules can never ship without inspection.",
		FailedFields: map[string]any{
			"profile_group.default": nil,
		},
	}}
}

func zoneProtectionProfile(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, z := range cfg.Zones {
		f := engine.Finding{Object: engine.ObjectRef{Section: "network", Feature: "zone", Name: z.Name, Location: z.Location}}
		switch {
		case !z.HasInterfaces():
			f.Verdict = engine.Note
			f.Message = "Zone has no interfaces assigned; attach a Zone Protection profile when it goes into service, or remove the unused zone."
		case z.ZoneProtectionProfile == "":
			f.Verdict = engine.Fail
			f.Message = "Zone has no Zone Protection profile; it has no flood, reconnaissance, or packet-based attack protection."
			f.FailedFields = map[string]any{"network.zone_protection_profile": ""}
		default:
			f.Verdict = engine.Pass
		}
		out = append(out, f)
	}
	return out
}

func ntpRedundant(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	obj := engine.ObjectRef{Section: "device", Feature: "device_setup_services"}
	d := cfg.Device
	f := engine.Finding{Object: obj, Verdict: engine.Pass}
	switch {
	case d.NTPPrimary == "" && d.NTPSecondary == "":
		f.Verdict = engine.Fail
		f.Message = "No NTP servers configured; accurate time is required for log correlation, certificate validation, and scheduled updates."
		f.FailedFields = map[string]any{"primary_ntp": "", "secondary_ntp": ""}
	case d.NTPSecondary == "":
		f.Verdict = engine.Fail
		f.Message = "Only a primary NTP server is configured. Configure a secondary NTP server for time-source redundancy."
		f.FailedFields = map[string]any{"secondary_ntp": ""}
	}
	return []engine.Finding{f}
}

func passwordComplexity(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	obj := engine.ObjectRef{Section: "device", Feature: "device_setup_minimum_password_complexity"}
	d := cfg.Device
	f := engine.Finding{Object: obj, Verdict: engine.Pass}
	if !d.PasswordComplexityEnabled {
		f.Verdict = engine.Fail
		f.Message = "Minimum Password Complexity is disabled for local administrator accounts."
		f.FailedFields = map[string]any{"enabled": false}
		return []engine.Finding{f}
	}
	minLen := paramInt(meta, "min_length", 12)
	zeroed := map[string]any{}
	if d.PasswordMinLength < minLen {
		zeroed["minimum_length"] = d.PasswordMinLength
	}
	if d.PasswordMinUppercase < 1 {
		zeroed["minimum_uppercase_letters"] = d.PasswordMinUppercase
	}
	if d.PasswordMinLowercase < 1 {
		zeroed["minimum_lowercase_letters"] = d.PasswordMinLowercase
	}
	if d.PasswordMinNumeric < 1 {
		zeroed["minimum_numeric_letters"] = d.PasswordMinNumeric
	}
	if !d.PasswordBlockUsername {
		zeroed["block_username_inclusion"] = false
	}
	if len(zeroed) > 0 {
		f.Verdict = engine.Fail
		f.Message = fmt.Sprintf("Password complexity is enabled but weak: one or more requirements are unset or below the configured minimum (length >= %d, at least one of each character class, username-inclusion blocking). See failed fields for the offending settings.", minLen)
		f.FailedFields = zeroed
	}
	return []engine.Finding{f}
}

// --- helpers -----------------------------------------------------------------

func listIsAny(l []string) bool {
	return len(l) == 0 || (len(l) == 1 && l[0] == "any")
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func paramInt(meta engine.CheckMeta, name string, def int) int {
	if v, ok := meta.Params[name]; ok {
		if n, ok := v.(int); ok {
			return n
		}
	}
	return def
}
