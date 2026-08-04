package checks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gitupcourt/open-pan-bpa/internal/engine"
	"github.com/gitupcourt/open-pan-bpa/internal/model"
)

// profileRegistry returns the security-profile evaluators.
func profileRegistry() engine.Registry {
	return engine.Registry{
		"av_decoder_actions":     avDecoderField(func(d model.AVDecoder) string { return d.Action }, "action"),
		"av_wildfire_actions":    avDecoderField(func(d model.AVDecoder) string { return d.WildfireAction }, "wildfire-action"),
		"av_mlav_actions":        avDecoderField(func(d model.AVDecoder) string { return d.MlavAction }, "mlav-action"),
		"av_mlav_engines":        avMlavEngines,
		"av_threat_exceptions":   avThreatExceptions,
		"av_app_exceptions":      avAppExceptions,
		"av_packet_capture":      avPacketCapture,
		"av_reset_client_server": avResetClientServer,
		"fb_best_practice_rules": fbBestPracticeRules,
		"wf_forward_all":         wfForwardAll,
		"wf_inline_cloud":        wfInlineCloud,
		"lf_external_forwarding": lfExternalForwarding,
		"lf_log_type":            lfLogType,
	}
}

func avObject(p model.AntivirusProfile) engine.ObjectRef {
	return engine.ObjectRef{Section: "objects", Feature: "antivirus_profile", Name: p.Name, Location: p.Location}
}

// avDecoderField builds an evaluator enforcing reset-both on one decoder
// action column. Decoders whose content default is already reset-both
// (ftp/http/http2/smb) may also leave the field at "default"/unset; the
// mail-protocol decoders (imap/pop3/smtp) need an explicit reset-both.
func avDecoderField(get func(model.AVDecoder) string, field string) engine.Evaluator {
	return func(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
		var out []engine.Finding
		for _, p := range cfg.AntivirusProfiles {
			f := engine.Finding{Object: avObject(p), Verdict: engine.Pass}
			offenders := map[string]any{}
			for _, name := range model.AVDecoderNames {
				v := get(p.Decoder(name))
				if v == "" {
					v = "default"
				}
				ok := v == "reset-both" || (v == "default" && model.AVDecodersDefaultResetBoth[name])
				if !ok {
					offenders[name] = v
				}
			}
			if len(offenders) > 0 {
				f.Verdict = engine.Fail
				f.Message = fmt.Sprintf("Decoder %s is not reset-both for: %s. Mail decoders inherit a weaker content default, so set reset-both explicitly.",
					field, joinKeys(offenders))
				f.FailedFields = offenders
			}
			out = append(out, f)
		}
		return out
	}
}

func avMlavEngines(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.AntivirusProfiles {
		f := engine.Finding{Object: avObject(p), Verdict: engine.Pass}
		offenders := map[string]any{}
		for name, action := range p.MlavEngines {
			if action != "enable" {
				offenders[name] = action
			}
		}
		if len(offenders) > 0 {
			f.Verdict = engine.Fail
			f.Message = "WildFire Inline ML models are not fully enabled (alert-only or disabled models detect but don't block): " + joinKeys(offenders) + "."
			f.FailedFields = offenders
		}
		out = append(out, f)
	}
	return out
}

func avThreatExceptions(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.AntivirusProfiles {
		f := engine.Finding{Object: avObject(p), Verdict: engine.Pass}
		if len(p.ThreatExceptions) > 0 {
			f.Verdict = engine.Fail
			f.Message = fmt.Sprintf("Profile carries %d threat exception(s); excepted signatures are never enforced. Confirmed false positives belong in a support case, then remove the exception.", len(p.ThreatExceptions))
			f.FailedFields = map[string]any{"threat_exceptions": p.ThreatExceptions}
		}
		out = append(out, f)
	}
	return out
}

func avAppExceptions(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.AntivirusProfiles {
		f := engine.Finding{Object: avObject(p), Verdict: engine.Pass}
		allowed := map[string]any{}
		for app, action := range p.AppExceptions {
			if action == "allow" {
				allowed[app] = action
			}
		}
		if len(allowed) > 0 {
			f.Verdict = engine.Fail
			f.Message = "Applications excepted from antivirus inspection (action allow): " + joinKeys(allowed) + ". Traffic for these apps is never scanned."
			f.FailedFields = allowed
		}
		out = append(out, f)
	}
	return out
}

func avPacketCapture(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.AntivirusProfiles {
		f := engine.Finding{Object: avObject(p), Verdict: engine.Pass}
		if p.PacketCapture {
			f.Verdict = engine.Fail
			f.Message = "Packet capture is enabled on a broadly applied Antivirus profile; it stresses logging resources. Enable it only on a narrow investigation profile."
			f.FailedFields = map[string]any{"packet_capture": true}
		}
		out = append(out, f)
	}
	return out
}

func avResetClientServer(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.AntivirusProfiles {
		f := engine.Finding{Object: avObject(p), Verdict: engine.Pass}
		partial := map[string]any{}
		for _, d := range p.Decoders {
			for field, v := range map[string]string{"action": d.Action, "wildfire-action": d.WildfireAction} {
				if v == "reset-client" || v == "reset-server" {
					partial[d.Name+"."+field] = v
				}
			}
		}
		if len(partial) > 0 {
			f.Verdict = engine.Fail
			f.Message = "One-sided resets leave the other end of the connection open; use reset-both unless a documented business reason requires otherwise: " + joinKeys(partial) + "."
			f.FailedFields = partial
		}
		out = append(out, f)
	}
	return out
}

// fbRequiredBlockTypes is the reference block list for File Blocking rules.
var fbRequiredBlockTypes = []string{
	"7z", "bat", "chm", "class", "cpl", "dll", "hlp", "hta",
	"jar", "ocx", "pif", "scr", "torrent", "vbe", "wsf",
}

// fbBestPracticeRules mirrors the reference engine's observed semantics: the
// profile needs an alert rule for all other file types (any/any/both) and at
// least one block rule (any/both) whose types stay WITHIN the reference
// malicious-type list. Types beyond the list, or rules with actions other
// than block/alert (continue prompts, encrypted-file blocks), fail; a block
// list that covers only part of the reference list still passes the
// reference engine, so we report missing types as advisory detail only.
func fbBestPracticeRules(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	required := map[string]bool{}
	for _, t := range fbRequiredBlockTypes {
		required[t] = true
	}
	var out []engine.Finding
	for _, p := range cfg.FileBlockingProfiles {
		f := engine.Finding{
			Object:  engine.ObjectRef{Section: "objects", Feature: "file_blocking_profile", Name: p.Name, Location: p.Location},
			Verdict: engine.Pass,
		}
		problems := map[string]any{}
		var blockOK, alertOK bool
		for _, r := range p.Rules {
			anyApp := len(r.Applications) == 1 && r.Applications[0] == "any"
			switch r.Action {
			case "block":
				_, extra := diffSets(required, r.FileTypes)
				switch {
				case len(extra) > 0:
					problems["rule:"+r.Name] = map[string]any{"types_beyond_reference_list": extra,
						"detail": "types outside the reference block list must fall through to the alert rule"}
				case !anyApp || r.Direction != "both":
					problems["rule:"+r.Name] = map[string]any{"application": r.Applications, "direction": r.Direction}
				default:
					blockOK = true
				}
			case "alert":
				if anyApp && r.Direction == "both" && len(r.FileTypes) == 1 && r.FileTypes[0] == "any" {
					alertOK = true
				}
			default:
				problems["rule:"+r.Name] = map[string]any{"action": r.Action,
					"detail": "file types outside the block list must fall through to alert"}
			}
		}
		if !blockOK && len(problems) == 0 {
			problems["block_rule"] = "no compliant block rule (reference file types, any application, both directions)"
		}
		if !alertOK {
			problems["alert_rule"] = "no alert rule covering all other file types (any/any/both)"
		}
		if len(problems) > 0 {
			f.Verdict = engine.Fail
			f.Message = "File Blocking profile deviates from the reference posture (block within the malicious-type list; alert on everything else)."
			f.FailedFields = problems
		}
		out = append(out, f)
	}
	return out
}

func wfForwardAll(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.WildfireProfiles {
		f := engine.Finding{
			Object:  engine.ObjectRef{Section: "objects", Feature: "wildfire_analysis_profile", Name: p.Name, Location: p.Location},
			Verdict: engine.Fail,
		}
		// Reference-verified: direction is NOT part of this check (an
		// upload-only rule passes); the requirement is any app + any type.
		for _, r := range p.Rules {
			if len(r.Applications) == 1 && r.Applications[0] == "any" &&
				len(r.FileTypes) == 1 && r.FileTypes[0] == "any" {
				f.Verdict = engine.Pass
				break
			}
		}
		if f.Verdict == engine.Fail {
			f.Message = "No rule forwards all file types for all applications; unforwarded files are never analyzed."
			f.FailedFields = map[string]any{"rules": len(p.Rules)}
		}
		out = append(out, f)
	}
	return out
}

func wfInlineCloud(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.WildfireProfiles {
		f := engine.Finding{
			Object:  engine.ObjectRef{Section: "objects", Feature: "wildfire_analysis_profile", Name: p.Name, Location: p.Location},
			Verdict: engine.Pass,
		}
		if !p.CloudInlineAnalysis {
			f.Verdict = engine.Fail
			f.Message = "Inline Cloud Analysis is disabled; in-line ML verdicts on zero-day files are skipped."
			f.FailedFields = map[string]any{"cloud_inline_analysis": "no"}
		}
		out = append(out, f)
	}
	return out
}

func lfObject(p model.LogForwardingProfile) engine.ObjectRef {
	return engine.ObjectRef{Section: "objects", Feature: "log_forwarding_profile", Name: p.Name, Location: p.Location}
}

func lfExternalForwarding(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.LogForwardingProfiles {
		f := engine.Finding{Object: lfObject(p), Verdict: engine.Fail}
		for _, m := range p.Matches {
			if m.HasDestination() {
				f.Verdict = engine.Pass
				break
			}
		}
		if f.Verdict == engine.Fail {
			f.Message = "Profile forwards nothing off-box; on-box storage rotates and evidence is lost."
			f.FailedFields = map[string]any{"match_list_with_destination": 0}
		}
		out = append(out, f)
	}
	return out
}

// lfLogType checks that the profile forwards a specific log type, taken from
// the check's log_type param.
func lfLogType(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	want, _ := meta.Params["log_type"].(string)
	var out []engine.Finding
	for _, p := range cfg.LogForwardingProfiles {
		f := engine.Finding{Object: lfObject(p), Verdict: engine.Fail}
		for _, m := range p.Matches {
			if m.LogType == want && m.HasDestination() {
				f.Verdict = engine.Pass
				break
			}
		}
		if f.Verdict == engine.Fail {
			f.Message = fmt.Sprintf("Profile has no forwarding match for %s logs; that log stream stays on-box only.", want)
			f.FailedFields = map[string]any{"log_type": want}
		}
		out = append(out, f)
	}
	return out
}

// --- helpers ---

func joinKeys(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

// diffSets returns required-elements missing from got, and got-elements not
// in required ("any" counts as unlisted).
func diffSets(required map[string]bool, got []string) (missing, extra []string) {
	gotSet := map[string]bool{}
	for _, g := range got {
		gotSet[g] = true
		if !required[g] {
			extra = append(extra, g)
		}
	}
	for r := range required {
		if !gotSet[r] {
			missing = append(missing, r)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}
