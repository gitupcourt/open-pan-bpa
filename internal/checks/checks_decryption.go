package checks

import (
	"github.com/gitupcourt/open-pan-bpa/internal/engine"
	"github.com/gitupcourt/open-pan-bpa/internal/model"
)

// decryptionRegistry returns Decryption-profile evaluators.
func decryptionRegistry() engine.Registry {
	return engine.Registry{
		"dp_forward_proxy":      dpFlagsAllYes("ssl-forward-proxy", func(p model.DecryptionProfile) map[string]string { return p.ForwardProxy }, dpForwardProxyFlags, map[string]string{"strip-alpn": "no"}),
		"dp_inbound_inspection": dpFlagsAllYes("ssl-inbound-proxy", func(p model.DecryptionProfile) map[string]string { return p.InboundProxy }, dpInboundFlags, nil),
		"dp_ssh_proxy":          dpFlagsAllYes("ssh-proxy", func(p model.DecryptionProfile) map[string]string { return p.SSHProxy }, dpSSHFlags, nil),
		"dp_no_decrypt_expired": dpNoProxyFlag("block-expired-certificate", "Sessions with expired certificates in no-decrypt traffic are not blocked."),
		"dp_no_decrypt_untrust": dpNoProxyFlag("block-untrusted-issuer", "Sessions from untrusted issuers in no-decrypt traffic are not blocked."),
		"dp_tls_versions":       dpTLSVersions,
		"dp_encryption_algos":   dpDisabledAlgos([]string{"enc-algo-3des", "enc-algo-rc4", "enc-algo-aes-128-cbc", "enc-algo-aes-256-cbc", "enc-algo-aes-128-gcm"}, "Deprecated encryption algorithms are enabled; only AES-256-GCM and CHACHA20-POLY1305 meet the quantum-safe bar."),
		"dp_auth_algos":         dpDisabledAlgos([]string{"auth-algo-sha1", "auth-algo-md5"}, "Deprecated handshake authentication algorithms are enabled; require SHA-256 or SHA-384."),
		"dp_pqc_key_exchange":   dpPQC,
	}
}

func dpObject(p model.DecryptionProfile) engine.ObjectRef {
	return engine.ObjectRef{Section: "objects", Feature: "decryption_profile", Name: p.Name, Location: p.Location}
}

var dpForwardProxyFlags = []string{
	"auto-include-altname", "block-client-cert", "block-expired-certificate",
	"block-if-hsm-unavailable", "block-if-no-resource", "block-timeout-cert",
	"block-unknown-cert", "block-unsupported-cipher", "block-unsupported-version",
	"block-untrusted-issuer", "restrict-cert-exts",
}

var dpInboundFlags = []string{
	"block-if-hsm-unavailable", "block-if-no-resource",
	"block-tls13-downgrade-no-resource", "block-unsupported-cipher",
	"block-unsupported-version",
}

var dpSSHFlags = []string{
	"block-if-no-resource", "block-ssh-errors",
	"block-unsupported-alg", "block-unsupported-version",
}

// dpFlagsAllYes: every flag in required must be "yes" (absent = "no");
// exceptions maps flags with a different expected value.
func dpFlagsAllYes(section string, get func(model.DecryptionProfile) map[string]string, required []string, exceptions map[string]string) engine.Evaluator {
	return func(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
		var out []engine.Finding
		for _, p := range cfg.DecryptionProfiles {
			f := engine.Finding{Object: dpObject(p), Verdict: engine.Pass}
			flags := get(p)
			offenders := map[string]any{}
			for _, name := range required {
				v := flags[name]
				if v == "" {
					v = "no"
				}
				if v != "yes" {
					offenders[section+"."+name] = v
				}
			}
			for name, want := range exceptions {
				v := flags[name]
				if v == "" {
					v = "no"
				}
				if v != want {
					offenders[section+"."+name] = v
				}
			}
			if len(offenders) > 0 {
				f.Verdict = engine.Fail
				f.Message = "Decryption profile " + section + " protections are not fully enabled; each disabled block setting is a session class that proceeds uninspected or unverified."
				f.FailedFields = offenders
			}
			out = append(out, f)
		}
		return out
	}
}

func dpNoProxyFlag(flag, message string) engine.Evaluator {
	return func(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
		var out []engine.Finding
		for _, p := range cfg.DecryptionProfiles {
			f := engine.Finding{Object: dpObject(p), Verdict: engine.Pass}
			v := p.NoProxy[flag]
			if v == "" {
				v = "no"
			}
			if v != "yes" {
				f.Verdict = engine.Fail
				f.Message = message
				f.FailedFields = map[string]any{"ssl-no-proxy." + flag: v}
			}
			out = append(out, f)
		}
		return out
	}
}

func dpTLSVersions(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.DecryptionProfiles {
		f := engine.Finding{Object: dpObject(p), Verdict: engine.Pass}
		minV := p.ProtocolSettings["min-version"]
		if minV != "tls1-2" && minV != "tls1-3" {
			if minV == "" {
				minV = "default (below TLS 1.2)"
			}
			f.Verdict = engine.Fail
			f.Message = "Minimum SSL protocol version is below TLS 1.2; downgraded handshakes expose deprecated protocol weaknesses."
			f.FailedFields = map[string]any{"ssl-protocol-settings.min-version": minV}
		}
		out = append(out, f)
	}
	return out
}

// dpAlgoDefaultOff lists algorithm flags whose content default is already
// disabled — absence passes; everything else defaults to enabled.
var dpAlgoDefaultOff = map[string]bool{"auth-algo-md5": true}

func dpDisabledAlgos(algos []string, message string) engine.Evaluator {
	return func(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
		var out []engine.Finding
		for _, p := range cfg.DecryptionProfiles {
			f := engine.Finding{Object: dpObject(p), Verdict: engine.Pass}
			offenders := map[string]any{}
			for _, name := range algos {
				v, set := p.ProtocolSettings[name]
				if !set {
					if dpAlgoDefaultOff[name] {
						continue
					}
					v = "yes"
				}
				if v != "no" {
					offenders["ssl-protocol-settings."+name] = v
				}
			}
			if len(offenders) > 0 {
				f.Verdict = engine.Fail
				f.Message = message
				f.FailedFields = offenders
			}
			out = append(out, f)
		}
		return out
	}
}

func dpPQC(cfg *model.Config, _ engine.CheckMeta) []engine.Finding {
	var out []engine.Finding
	for _, p := range cfg.DecryptionProfiles {
		f := engine.Finding{Object: dpObject(p), Verdict: engine.Pass}
		std := p.ProtocolSettings["keyxchg-algo-pqc-standardized"]
		exp := p.ProtocolSettings["keyxchg-algo-pqc-non-standardized"]
		if std != "yes" && exp != "yes" {
			f.Verdict = engine.Fail
			f.Message = "No post-quantum key-exchange algorithm is enabled; harvested TLS sessions remain decryptable by future quantum capability."
			f.FailedFields = map[string]any{
				"ssl-protocol-settings.keyxchg-algo-pqc-standardized":     orNo(std),
				"ssl-protocol-settings.keyxchg-algo-pqc-non-standardized": orNo(exp),
			}
		}
		out = append(out, f)
	}
	return out
}

func orNo(s string) string {
	if s == "" {
		return "no"
	}
	return s
}
