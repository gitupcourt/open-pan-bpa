package checks

import (
	"fmt"
	"strings"

	"github.com/gitupcourt/open-pan-bpa/internal/engine"
	"github.com/gitupcourt/open-pan-bpa/internal/model"
)

// updatesRegistry: dynamic updates, log settings, server profiles,
// certificates, roles, and sequences.
func updatesRegistry() engine.Registry {
	return engine.Registry{
		"du_antivirus":       duAntivirus,
		"du_apps_threats":    duAppsThreats,
		"du_wildfire":        duWildfire,
		"du_sync_peer_av":    duSyncPeer("anti-virus"),
		"du_sync_peer_at":    duSyncPeer("threats"),
		"du_gp_datafile":     duGPHourly("global-protect-datafile"),
		"du_gp_clientless":   duGPHourly("global-protect-clientless-vpn"),
		"ls_system_low":      lsSystem([]string{"informational", "low"}),
		"ls_system_high":     lsSystem([]string{"medium", "high", "critical"}),
		"ls_config":          lsConfig,
		"sprof_syslog_ssl":   sprofSyslogSSL,
		"sprof_tacplus_chap": sprofTacplusCHAP,
		"sprof_ldap_ssl":     sprofLDAPFlag("ssl", "LDAP binds without TLS transmit directory credentials in cleartext."),
		"sprof_ldap_verify":  sprofLDAPFlag("verify-server-certificate", "LDAP over TLS without certificate verification accepts an impersonated directory."),
		"sprof_ldap_redund":  sprofLDAPRedundancy,
		"cert_trust_split":   certTrustSplit,
		"tls_profile_vers":   tlsProfileVersions,
		"role_custom":        roleCustom,
		"authseq_secondary":  authseqSecondary,
	}
}

func duObject() engine.ObjectRef {
	return engine.ObjectRef{Section: "device", Feature: "dynamic_updates"}
}

func duFinding(pass bool, msg string, ff map[string]any) []engine.Finding {
	f := engine.Finding{Object: duObject(), Verdict: engine.Pass}
	if !pass {
		f.Verdict = engine.Fail
		f.Message = msg
		f.FailedFields = ff
	}
	return []engine.Finding{f}
}

func duAntivirus(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	s, ok := cfg.UpdateSchedules["anti-virus"]
	pass := ok && s.Frequency == "hourly" && s.Action == "download-and-install" && s.Threshold == 0
	return duFinding(pass,
		"Antivirus content should download-and-install hourly with no threshold; slower schedules widen the signature gap.",
		map[string]any{"anti-virus": describeSchedule(s, ok)})
}

func duAppsThreats(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	s, ok := cfg.UpdateSchedules["threats"]
	freqOK := s.Frequency == "hourly" || s.Frequency == "daily" || s.Frequency == "every-30-mins" || s.Frequency == "every-hour"
	pass := ok && freqOK && s.Action == "download-and-install" && s.Threshold <= 48
	return duFinding(pass,
		"Apps and Threats content should download-and-install at daily frequency or faster, with any threshold at most 48 hours.",
		map[string]any{"threats": describeSchedule(s, ok)})
}

func duWildfire(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	s, ok := cfg.UpdateSchedules["wildfire"]
	pass := ok && (s.Frequency == "real-time" || s.Frequency == "every-min")
	return duFinding(pass,
		"WildFire content should update in real time; scheduled WildFire updates forfeit the minutes-after-discovery signatures.",
		map[string]any{"wildfire": describeSchedule(s, ok)})
}

// duSyncPeer — reference-verified inversion of the check title: HA pairs are
// expected to have content sync-to-peer enabled.
func duSyncPeer(content string) engine.Evaluator {
	return func(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
		if !cfg.HAEnabled {
			return []engine.Finding{{Object: duObject(), Verdict: engine.Pass}}
		}
		s, ok := cfg.UpdateSchedules[content]
		pass := ok && s.SyncToPeer == "yes"
		return duFinding(pass,
			fmt.Sprintf("HA is enabled but %s content sync-to-peer is off; peers can run divergent content versions after failover.", content),
			map[string]any{content + ".sync-to-peer": s.SyncToPeer})
	}
}

func duGPHourly(content string) engine.Evaluator {
	return func(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
		s, ok := cfg.UpdateSchedules[content]
		pass := ok && s.Frequency == "hourly" && s.Action == "download-and-install"
		return duFinding(pass,
			fmt.Sprintf("%s content should download-and-install hourly.", content),
			map[string]any{content: describeSchedule(s, ok)})
	}
}

func describeSchedule(s model.UpdateSchedule, ok bool) string {
	if !ok {
		return "no schedule configured"
	}
	d := s.Frequency
	if s.Action != "" {
		d += "/" + s.Action
	}
	if s.Threshold > 0 {
		d += fmt.Sprintf(" threshold=%d", s.Threshold)
	}
	return d
}

// lsSystem: severities must be covered by a forwarding match-list (an
// unfiltered match forwards everything and covers both checks).
func lsSystem(severities []string) engine.Evaluator {
	return func(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
		f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature}, Verdict: engine.Pass}
		if !severitiesForwarded(cfg.SystemLogMatches, severities) {
			f.Verdict = engine.Fail
			f.Message = fmt.Sprintf("System logs at severities %v are not forwarded off-box.", severities)
			f.FailedFields = map[string]any{"severities": severities}
		}
		return []engine.Finding{f}
	}
}

func severitiesForwarded(matches []model.SimpleLogMatch, severities []string) bool {
	for _, sev := range severities {
		covered := false
		for _, m := range matches {
			if !m.HasDest {
				continue
			}
			if m.Filter == "" || m.Filter == "All Logs" || containsWord(m.Filter, sev) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func containsWord(filter, word string) bool {
	return len(filter) > 0 && (stringsContains(filter, word))
}

func lsConfig(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature}, Verdict: engine.Pass}
	ok := false
	for _, m := range cfg.ConfigLogMatches {
		if m.HasDest && (m.Filter == "" || m.Filter == "All Logs") {
			ok = true
			break
		}
	}
	if !ok {
		f.Verdict = engine.Fail
		f.Message = "Configuration logs are not forwarded off-box; config-change audit trails vanish with on-box rotation."
		f.FailedFields = map[string]any{"config.match-list": "no unfiltered forwarding match"}
	}
	return []engine.Finding{f}
}

func serverProfileObject(p model.ServerProfile, feature string) engine.ObjectRef {
	return engine.ObjectRef{Section: "device", Feature: feature, Name: p.Name, Location: p.Location}
}

func sprofSyslogSSL(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.ServerProfiles {
		if p.Kind != "syslog" {
			continue
		}
		f := engine.Finding{Object: serverProfileObject(p, meta.Feature), Verdict: engine.Pass}
		var insecure []string
		for i, t := range p.Transports {
			if t != "SSL" {
				insecure = append(insecure, fmt.Sprintf("server[%d]=%s", i, orDefault(t)))
			}
		}
		if len(insecure) > 0 {
			f.Verdict = engine.Fail
			f.Message = "Syslog transport is not SSL; forwarded logs (and what they reveal) traverse the network readable and forgeable."
			f.FailedFields = map[string]any{"transports": insecure}
		}
		out = append(out, f)
	}
	return out
}

func sprofTacplusCHAP(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.ServerProfiles {
		if p.Kind != "tacplus" {
			continue
		}
		f := engine.Finding{Object: serverProfileObject(p, meta.Feature), Verdict: engine.Pass}
		if p.Flags["protocol"] != "CHAP" {
			f.Verdict = engine.Fail
			f.Message = "TACACS+ authentication protocol is not CHAP; PAP transmits the password to the server in a reversible form."
			f.FailedFields = map[string]any{"protocol": orDefault(p.Flags["protocol"])}
		}
		out = append(out, f)
	}
	return out
}

func sprofLDAPFlag(flag, message string) engine.Evaluator {
	return func(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
		var out []engine.Finding
		for _, p := range cfg.ServerProfiles {
			if p.Kind != "ldap" {
				continue
			}
			f := engine.Finding{Object: serverProfileObject(p, meta.Feature), Verdict: engine.Pass}
			v := p.Flags[flag]
			// ssl defaults to yes on PAN-OS; verify-server-certificate to no.
			if v == "" && flag == "ssl" {
				v = "yes"
			}
			if v != "yes" {
				f.Verdict = engine.Fail
				f.Message = message
				f.FailedFields = map[string]any{flag: orNo(v)}
			}
			out = append(out, f)
		}
		return out
	}
}

func sprofLDAPRedundancy(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.ServerProfiles {
		if p.Kind != "ldap" {
			continue
		}
		f := engine.Finding{Object: serverProfileObject(p, meta.Feature), Verdict: engine.Pass}
		if p.ServerCount < 2 {
			f.Verdict = engine.Fail
			f.Message = "The LDAP profile lists a single server; directory outage means authentication outage."
			f.FailedFields = map[string]any{"servers": p.ServerCount}
		}
		out = append(out, f)
	}
	return out
}

func certTrustSplit(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, c := range cfg.Certificates {
		f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature, Name: c.Name, Location: c.Location}, Verdict: engine.Pass}
		if c.ForwardTrust && c.ForwardUntrust {
			f.Verdict = engine.Fail
			f.Message = "The same certificate serves as both Forward Trust and Forward Untrust CA; untrusted sites then present a certificate clients trust."
			f.FailedFields = map[string]any{"forward-trust-ca": "yes", "forward-untrust-ca": "yes"}
		}
		out = append(out, f)
	}
	return out
}

func tlsProfileVersions(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.SSLTLSProfiles {
		f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature, Name: p.Name, Location: p.Location}, Verdict: engine.Pass}
		// Reference-verified: only the minimum version is enforced (profiles
		// with an explicit max below "max" still pass the reference engine).
		if p.MinVersion != "tls1-2" && p.MinVersion != "tls1-3" {
			f.Verdict = engine.Fail
			f.Message = "SSL/TLS service profile allows protocol versions below TLS 1.2."
			f.FailedFields = map[string]any{"min-version": orDefault(p.MinVersion)}
		}
		out = append(out, f)
	}
	return out
}

func roleCustom(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, r := range cfg.AdminRoles {
		f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature, Name: r.Name}, Verdict: engine.Pass}
		if !r.HasDeviceRole && !r.HasVsysRole {
			f.Verdict = engine.Fail
			f.Message = "The admin role defines no device or vsys permissions; an empty custom role is either unused clutter or a misconfiguration."
			f.FailedFields = map[string]any{"role": "empty"}
		}
		out = append(out, f)
	}
	return out
}

func authseqSecondary(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, s := range cfg.AuthSequences {
		f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature, Name: s.Name}, Verdict: engine.Pass}
		if s.ProfileCount < 2 {
			f.Verdict = engine.Fail
			f.Message = "The authentication sequence has fewer than two profiles; a sequence exists to provide a fallback when the primary is unreachable."
			f.FailedFields = map[string]any{"authentication-profiles": s.ProfileCount}
		}
		out = append(out, f)
	}
	return out
}

func stringsContains(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
