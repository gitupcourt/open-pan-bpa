package checks

import (
	"fmt"

	"github.com/gitupcourt/open-pan-bpa/internal/engine"
	"github.com/gitupcourt/open-pan-bpa/internal/model"
)

// networkRegistry: HA, zone protection, interface management, GlobalProtect
// gateways, crypto profiles, and per-zone packet buffer protection.
func networkRegistry() engine.Registry {
	return engine.Registry{
		"ha_config_sync": haCheck(func(h model.HAConfig) (bool, map[string]any) {
			return !h.ConfigSyncDisabled, map[string]any{"configuration-synchronization": "no"}
		}, "HA configuration synchronization is disabled; peers drift apart until failover surprises you."),
		"ha_backup_links": haCheck(func(h model.HAConfig) (bool, map[string]any) {
			return h.PeerIPBackup != "" || h.HA1BackupPort != "", map[string]any{"peer-ip-backup": "", "ha1-backup": ""}
		}, "No HA1 backup path exists; losing the single control link triggers split-brain."),
		"ha_passive_link": haPassiveLink,
		"ha_heartbeat":    haHeartbeat,
		"ha_timers":       haTimers,
		"ha_ha1_encryption": haCheck(func(h model.HAConfig) (bool, map[string]any) {
			return h.HA1Encryption == "yes", map[string]any{"ha1.encryption.enabled": "no"}
		}, "HA1 control traffic is unencrypted; session and config sync cross the wire in cleartext."),
		"ha_state_sync": haCheck(func(h model.HAConfig) (bool, map[string]any) {
			return !h.StateSyncDisabled, map[string]any{"state-synchronization": "no"}
		}, "HA2 session synchronization is disabled; failover drops every active session."),
		// The reference engine is provably inconsistent on this check: two
		// devices with byte-identical normalized keep-alive config received
		// opposite verdicts. We take the honest reading (disabled = fail);
		// the divergence is allowlisted in the conformance harness.
		"ha_ha2_keepalive": haCheck(func(h model.HAConfig) (bool, map[string]any) {
			return h.HA2KeepAlive == "yes", map[string]any{"ha2-keep-alive.enabled": "disabled or unset"}
		}, "HA2 keep-alive is disabled; a dead session-sync path goes unnoticed until failover."),
		"ha_aa_ha3":           haActiveActive(func(h model.HAConfig) bool { return h.HA3Configured }, "Active/Active HA without an HA3 interface cannot forward asymmetric packets between peers."),
		"ha_aa_session_owner": haActiveActive(func(h model.HAConfig) bool { return h.SessionOwnerFirstPkt }, "Active/Active session owner should be First Packet to avoid cross-peer inspection hops."),
		"ha_monitoring":       haMonitoring,
		"ha_link_group":       haLinkGroup,
		"ha_path_group":       haPathGroup,
		"zpp_recon":           zppRecon,
		"zpp_packet_attack":   zppPacketAttack,
		"ifmgmt_encrypted":    ifmgmtEncrypted,
		"zone_pbp":            zonePBP,
		"gpgw_tls":            gpgwTLS,
		"gpgw_client_auth":    gpgwClientAuth,
		"gpgw_split_tunnel":   gpgwSplitTunnel,
		"gpgw_satellite":      gpgwSatellite,
		"crypto_ike_kem":      cryptoKEM(func(cfg *model.Config) []model.CryptoProfile { return cfg.IKEProfiles }, false),
		"crypto_ipsec_kem":    cryptoKEM(func(cfg *model.Config) []model.CryptoProfile { return cfg.IPSecProfiles }, true),
	}
}

func haObject(meta engine.CheckMeta) engine.ObjectRef {
	return engine.ObjectRef{Section: "device", Feature: meta.Feature}
}

// haCheck wraps a condition that only applies when HA is enabled.
func haCheck(cond func(model.HAConfig) (bool, map[string]any), message string) engine.Evaluator {
	return func(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
		f := engine.Finding{Object: haObject(meta), Verdict: engine.Pass}
		if cfg.HAEnabled {
			if ok, ff := cond(cfg.HA); !ok {
				f.Verdict = engine.Fail
				f.Message = message
				f.FailedFields = ff
			}
		}
		return []engine.Finding{f}
	}
}

func haPassiveLink(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	f := engine.Finding{Object: haObject(meta), Verdict: engine.Pass}
	if cfg.HAEnabled && !cfg.HA.ActiveActive && cfg.HA.PassiveLinkState != "" && cfg.HA.PassiveLinkState != "auto" {
		f.Verdict = engine.Fail
		f.Message = "Passive link state is 'shutdown'; 'auto' keeps passive links up so failover skips link-negotiation delay."
		f.FailedFields = map[string]any{"passive-link-state": cfg.HA.PassiveLinkState}
	}
	return []engine.Finding{f}
}

// haHeartbeat — reference-verified conditionality: heartbeat backup is only
// required when both HA1 and its backup ride in-band dataplane ports; an
// out-of-band (management) backup passes without it.
func haHeartbeat(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	f := engine.Finding{Object: haObject(meta), Verdict: engine.Pass}
	h := cfg.HA
	inband := func(port string) bool { return port != "" && port != "management" }
	if cfg.HAEnabled && h.HeartbeatBackup != "yes" && inband(h.HA1Port) && (h.HA1BackupPort == "" || inband(h.HA1BackupPort)) {
		f.Verdict = engine.Fail
		f.Message = "HA1 and its backup are both in-band with heartbeat backup disabled; a dataplane failure severs all HA communication at once."
		f.FailedFields = map[string]any{"heartbeat-backup": orNo(h.HeartbeatBackup), "ha1.port": h.HA1Port, "ha1-backup.port": h.HA1BackupPort}
	}
	return []engine.Finding{f}
}

func haTimers(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	f := engine.Finding{Object: haObject(meta), Verdict: engine.Pass}
	if cfg.HAEnabled && cfg.HA.TimersMode != "recommended" {
		f.Verdict = engine.Fail
		f.Message = "HA election timers are not set to Recommended; unvetted timer values cause flapping or slow failover."
		f.FailedFields = map[string]any{"election-option.timers": orDefault(cfg.HA.TimersMode)}
	}
	return []engine.Finding{f}
}

func haActiveActive(cond func(model.HAConfig) bool, message string) engine.Evaluator {
	return func(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
		f := engine.Finding{Object: haObject(meta), Verdict: engine.Pass}
		if cfg.HAEnabled && cfg.HA.ActiveActive && !cond(cfg.HA) {
			f.Verdict = engine.Fail
			f.Message = message
		}
		return []engine.Finding{f}
	}
}

func haMonitoring(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	f := engine.Finding{Object: haObject(meta), Verdict: engine.Pass}
	if cfg.HAEnabled && cfg.HA.LinkMonDisabled && cfg.HA.PathMonDisabled {
		f.Verdict = engine.Fail
		f.Message = "Both HA link and path monitoring are disabled; the pair cannot detect the failures it exists to survive."
		f.FailedFields = map[string]any{"link-monitoring": "no", "path-monitoring": "no"}
	}
	return []engine.Finding{f}
}

func haLinkGroup(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	f := engine.Finding{Object: haObject(meta), Verdict: engine.Pass}
	if cfg.HAEnabled && !cfg.HA.LinkMonDisabled && cfg.HA.LinkGroups == 0 {
		f.Verdict = engine.Fail
		f.Message = "Link monitoring is enabled but no link group is defined; nothing is actually monitored."
		f.FailedFields = map[string]any{"link-group": 0}
	}
	return []engine.Finding{f}
}

func haPathGroup(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	f := engine.Finding{Object: haObject(meta), Verdict: engine.Pass}
	if cfg.HAEnabled && !cfg.HA.PathMonDisabled && cfg.HA.PathGroups == 0 {
		f.Verdict = engine.Fail
		f.Message = "Path monitoring is enabled but no path group is defined; nothing is actually monitored."
		f.FailedFields = map[string]any{"path-group": 0}
	}
	return []engine.Finding{f}
}

func zppObject(p model.ZoneProtectionProfile, meta engine.CheckMeta) engine.ObjectRef {
	return engine.ObjectRef{Section: "network", Feature: meta.Feature, Name: p.Name, Location: p.Location}
}

func zppRecon(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.ZoneProtections {
		f := engine.Finding{Object: zppObject(p, meta), Verdict: engine.Pass}
		if p.ScanEntries == 0 {
			f.Verdict = engine.Fail
			f.Message = "Reconnaissance protection is not configured; port scans and host sweeps proceed unthrottled and unlogged."
			f.FailedFields = map[string]any{"scan": 0}
		}
		out = append(out, f)
	}
	return out
}

// zppPacketAttack element names, grounded from PAN's IronSkillet golden
// configuration and field config exports (set network profiles
// zone-protection-profile ...): discard-malformed-option,
// discard-overlapping-tcp-segment-mismatch, remove-tcp-timestamp.
var zppPacketCandidates = map[string][]string{
	"discard-malformed-option":                 {"discard-malformed-option"},
	"discard-overlapping-tcp-segment-mismatch": {"discard-overlapping-tcp-segment-mismatch"},
	"remove-tcp-timestamp":                     {"remove-tcp-timestamp"},
}

func zppPacketAttack(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.ZoneProtections {
		f := engine.Finding{Object: zppObject(p, meta), Verdict: engine.Pass}
		missing := map[string]any{}
		for label, candidates := range zppPacketCandidates {
			ok := false
			for _, name := range candidates {
				if p.PacketFlags[name] == "yes" {
					ok = true
					break
				}
			}
			if !ok {
				missing[label] = "no"
			}
		}
		if len(missing) > 0 {
			f.Verdict = engine.Fail
			f.Message = "Packet-based attack protections (malformed options, overlapping TCP segments, TCP timestamp stripping) are not enabled."
			f.FailedFields = missing
		}
		out = append(out, f)
	}
	return out
}

func ifmgmtEncrypted(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.InterfaceMgmt {
		f := engine.Finding{Object: engine.ObjectRef{Section: "network", Feature: meta.Feature, Name: p.Name, Location: p.Location}, Verdict: engine.Pass}
		bad := map[string]any{}
		if p.HTTP == "yes" {
			bad["http"] = "yes"
		}
		if p.Telnet == "yes" {
			bad["telnet"] = "yes"
		}
		if len(bad) > 0 {
			f.Verdict = engine.Fail
			f.Message = "The interface management profile permits unencrypted protocols; dataplane management interfaces deserve the same floor as the management port."
			f.FailedFields = bad
		}
		out = append(out, f)
	}
	return out
}

func zonePBP(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, z := range cfg.Zones {
		f := engine.Finding{Object: engine.ObjectRef{Section: "network", Feature: meta.Feature, Name: z.Name, Location: z.Location}, Verdict: engine.Pass}
		if !z.EnablePacketBufferProt {
			f.Verdict = engine.Fail
			f.Message = "Packet buffer protection is disabled on this zone; the zone can exhaust shared buffers unchecked."
			f.FailedFields = map[string]any{"enable-packet-buffer-protection": "no"}
		}
		out = append(out, f)
	}
	return out
}

func gpgwObject(g model.GPGateway, meta engine.CheckMeta) engine.ObjectRef {
	return engine.ObjectRef{Section: "network", Feature: meta.Feature, Name: g.Name, Location: g.Location}
}

// gpgwTLS — unlike the standalone TLS-profile check, the gateway variant is
// reference-verified to require max-version "max" as well.
func gpgwTLS(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	profiles := map[string]model.SSLTLSProfile{}
	for _, p := range cfg.SSLTLSProfiles {
		profiles[p.Name] = p
	}
	var out []engine.Finding
	for _, g := range cfg.GPGateways {
		f := engine.Finding{Object: gpgwObject(g, meta), Verdict: engine.Pass}
		p, ok := profiles[g.TLSProfile]
		switch {
		case g.TLSProfile == "" || !ok:
			f.Verdict = engine.Fail
			f.Message = "The gateway references no resolvable SSL/TLS service profile."
			f.FailedFields = map[string]any{"ssl-tls-service-profile": g.TLSProfile}
		case (p.MinVersion != "tls1-2" && p.MinVersion != "tls1-3") || (p.MaxVersion != "" && p.MaxVersion != "max"):
			f.Verdict = engine.Fail
			f.Message = "The gateway's TLS profile should require TLS 1.2 minimum with max version 'max' so newer protocol versions are never refused."
			f.FailedFields = map[string]any{"min-version": orDefault(p.MinVersion), "max-version": orDefault(p.MaxVersion)}
		}
		out = append(out, f)
	}
	return out
}

func gpgwClientAuth(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, g := range cfg.GPGateways {
		f := engine.Finding{Object: gpgwObject(g, meta), Verdict: engine.Pass}
		if !g.HasClientAuth && !g.HasCertProfile {
			f.Verdict = engine.Fail
			f.Message = "The gateway authenticates clients with neither a certificate profile nor an authentication profile."
			f.FailedFields = map[string]any{"client-auth": "none", "certificate-profile": ""}
		}
		out = append(out, f)
	}
	return out
}

func gpgwSplitTunnel(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, g := range cfg.GPGateways {
		f := engine.Finding{Object: gpgwObject(g, meta), Verdict: engine.Pass}
		if g.TunnelConfigs > 0 && g.TunnelsFullAccess < g.TunnelConfigs {
			f.Verdict = engine.Fail
			f.Message = fmt.Sprintf("%d of %d tunnel configs do not route all destinations (0.0.0.0/0) through the tunnel; split-tunneled traffic bypasses inspection entirely.", g.TunnelConfigs-g.TunnelsFullAccess, g.TunnelConfigs)
			f.FailedFields = map[string]any{"tunnel_configs_without_full_route": g.TunnelConfigs - g.TunnelsFullAccess}
		}
		out = append(out, f)
	}
	return out
}

func gpgwSatellite(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, g := range cfg.GPGateways {
		f := engine.Finding{Object: gpgwObject(g, meta), Verdict: engine.Pass}
		if g.HasSatellite && g.SatelliteReplay != "yes" {
			f.Verdict = engine.Fail
			f.Message = "The satellite tunnel configuration does not enable anti-replay; captured tunnel packets can be re-injected."
			f.FailedFields = map[string]any{"anti-replay": orNo(g.SatelliteReplay)}
		}
		out = append(out, f)
	}
	return out
}

// kemAlgos are the accepted post-quantum key-encapsulation values.
var kemAlgos = map[string]bool{}

func init() {
	for _, k := range []string{
		"kyber-512", "kyber-768", "kyber-1024", "bike-L1", "bike-L3", "bike-L5",
		"frodokem", "hqc", "classic-mceliece", "ntruprime-sntrup761",
		"mlkem512", "mlkem768", "mlkem1024",
	} {
		kemAlgos[k] = true
	}
}

// cryptoKEM: at least one AKE round must use a KEM. Reference evidence: for
// IPsec profiles an absent AKE block inherits all-DH defaults and fails; IKE
// profiles without AKE rounds pass.
func cryptoKEM(get func(*model.Config) []model.CryptoProfile, absentFails bool) engine.Evaluator {
	return func(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
		var out []engine.Finding
		for _, p := range get(cfg) {
			f := engine.Finding{Object: engine.ObjectRef{Section: "network", Feature: meta.Feature, Name: p.Name, Location: p.Location}, Verdict: engine.Pass}
			hasKEM := false
			for _, a := range p.AKE {
				if kemAlgos[a] {
					hasKEM = true
					break
				}
			}
			if !hasKEM && (len(p.AKE) > 0 || absentFails) {
				f.Verdict = engine.Fail
				f.Message = "No advanced key-exchange round uses a post-quantum KEM; classical Diffie-Hellman exchanges are harvestable against future quantum capability."
				f.FailedFields = map[string]any{"ake": p.AKE}
			}
			out = append(out, f)
		}
		return out
	}
}
