package checks

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/gitupcourt/open-pan-bpa/internal/engine"
	"github.com/gitupcourt/open-pan-bpa/internal/model"
)

// deviceRegistry returns device-setup evaluators. Each produces exactly one
// device-scope finding.
func deviceRegistry() engine.Registry {
	return engine.Registry{
		"dev_cert_expiration_check": devFlagYes(func(d model.Device) map[string]string { return d.MgmtFlags },
			"enable-certificate-expiration-check", "no", "Certificate expiration checking is disabled; expired device certificates fail silently instead of warning ahead of time."),
		"dev_unique_hostname":     devHostname,
		"dev_login_banner":        devLoginBanner,
		"dev_wildfire_cloud":      devWildfireCloud,
		"dev_auth_profile":        devAuthProfile,
		"dev_idle_timeout":        devIdleTimeout,
		"dev_failed_attempts":     devFailedAttempts,
		"dev_lockout_time":        devLockoutTime,
		"dev_api_key_lifetime":    devAPIKeyLifetime,
		"dev_permitted_ip":        devPermittedIP,
		"dev_permitted_ip_broad":  devPermittedIPBroad,
		"dev_mgmt_encrypted_only": devMgmtEncryptedOnly,
		"dev_update_server_verify": devFlagYes(func(d model.Device) map[string]string { return d.SysFlags },
			"server-verification", "yes", "Update-server identity verification is disabled; content updates could be fetched from an impersonated server."),
		"dev_fqdn_refresh":  devFQDNRefresh,
		"dev_xff_user_id":   devFlagYes(func(d model.Device) map[string]string { return d.CTDFlags }, "x-forwarded-for", "no", "X-Forwarded-For extraction is disabled; users behind downstream proxies are invisible to User-ID."),
		"dev_strip_xff":     devFlagYes(func(d model.Device) map[string]string { return d.CTDFlags }, "strip-x-fwd-for", "no", "X-Forwarded-For headers are not stripped outbound; internal client IPs leak to external servers."),
		"dev_rematch":       devFlagYes(func(d model.Device) map[string]string { return d.ConfigFlags }, "rematch", "yes", "Session rematch is disabled; existing sessions keep flowing under pre-change policy after a commit."),
		"dev_accel_aging":   devFlagYes(func(d model.Device) map[string]string { return d.SessionFlags }, "accelerated-aging", "yes", "Accelerated aging is disabled; idle sessions linger and consume the session table under load."),
		"dev_packet_buffer": devFlagYes(func(d model.Device) map[string]string { return d.SessionFlags }, "packet-buffer-protection-enable", "yes", "Global Packet Buffer Protection is disabled; buffer-exhaustion attacks degrade the whole dataplane."),
		"dev_tcp_ooo_queue": devFlagNo(func(d model.Device) map[string]string { return d.TCPFlags }, "bypass-exceed-oo-queue", "Segments exceeding the TCP out-of-order queue are forwarded uninspected."),
		"dev_tcp_ctd_queue": devFlagNo(func(d model.Device) map[string]string { return d.CTDFlags }, "tcp-bypass-exceed-queue", "Segments exceeding the TCP content-inspection queue are forwarded uninspected."),
		"dev_udp_ctd_queue": devFlagNo(func(d model.Device) map[string]string { return d.CTDFlags }, "udp-bypass-exceed-queue", "Datagrams exceeding the UDP content-inspection queue are forwarded uninspected."),
		"dev_appid_queue":   devFlagNo(func(d model.Device) map[string]string { return d.AppFlags }, "bypass-exceed-queue", "Segments exceeding the App-ID inspection queue are forwarded unidentified."),
		"dev_hit_count":     devFlagYes(func(d model.Device) map[string]string { return d.MgmtFlags }, "policy-rulebase-hit-count", "yes", "Policy rule hit counting is disabled; unused-rule cleanup loses its evidence base."),
		"dev_log_high_dp":   devFlagYes(func(d model.Device) map[string]string { return d.MgmtFlags }, "enable-log-high-dp-load", "no", "No system log is generated when the dataplane hits 100% load; capacity incidents go unrecorded."),
		"dev_telemetry":     devTelemetry,
		"dev_secure_conn":   devSecureConn,
	}
}

// devFlagYes: flag must be "yes"; when absent, defaultVal applies.
func devFlagYes(get func(model.Device) map[string]string, flag, defaultVal, message string) engine.Evaluator {
	return func(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
		v, ok := get(cfg.Device)[flag]
		if !ok {
			v = defaultVal
		}
		f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature}, Verdict: engine.Pass}
		if v != "yes" {
			f.Verdict = engine.Fail
			f.Message = message
			f.FailedFields = map[string]any{flag: v}
		}
		return []engine.Finding{f}
	}
}

// devFlagNo: flag must not be "yes"; absent counts as "no" (the safe default).
func devFlagNo(get func(model.Device) map[string]string, flag, message string) engine.Evaluator {
	return func(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
		v := get(cfg.Device)[flag]
		f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature}, Verdict: engine.Pass}
		if v == "yes" {
			f.Verdict = engine.Fail
			f.Message = message
			f.FailedFields = map[string]any{flag: v}
		}
		return []engine.Finding{f}
	}
}

var defaultHostnamePattern = regexp.MustCompile(`^(PA-\d+|PA-VM|firewall)$`)

func devHostname(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature}, Verdict: engine.Pass}
	if cfg.Hostname == "" || defaultHostnamePattern.MatchString(cfg.Hostname) {
		f.Verdict = engine.Fail
		f.Message = "The device uses a default or empty hostname; logs and alerts from it are unattributable at a glance."
		f.FailedFields = map[string]any{"hostname": cfg.Hostname}
	}
	return []engine.Finding{f}
}

func devLoginBanner(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature}, Verdict: engine.Pass}
	if strings.TrimSpace(cfg.Device.SysFlags["login-banner"]) == "" {
		f.Verdict = engine.Fail
		f.Message = "No login banner is configured; unauthorized-access warnings carry legal weight and belong on every management login."
		f.FailedFields = map[string]any{"login-banner": ""}
	}
	return []engine.Finding{f}
}

func devWildfireCloud(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature}, Verdict: engine.Pass}
	server := cfg.Device.WildfireSet["public-cloud-server"]
	if server == "" || server == "wildfire.paloaltonetworks.com" {
		f.Verdict = engine.Fail
		f.Message = "WildFire sample forwarding uses the global cloud; the regional cloud keeps samples in-jurisdiction and reduces round-trip."
		f.FailedFields = map[string]any{"public-cloud-server": orDefault(server)}
	}
	return []engine.Finding{f}
}

// devAuthProfile — reference-verified: the check looks at authentication
// profiles referenced by the administrator ACCOUNTS (or the device-wide
// authentication setting), not just Device > Setup > Authentication Settings.
func devAuthProfile(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature}, Verdict: engine.Pass}
	if cfg.Device.SysFlags["authentication-profile"] == "" && cfg.Device.AdminsWithAuthProfile == 0 {
		f.Verdict = engine.Fail
		f.Message = "No administrator authenticates through an external Authentication profile; management access rests entirely on local passwords."
		f.FailedFields = map[string]any{"authentication-profile": "", "admins_with_auth_profile": 0}
	}
	return []engine.Finding{f}
}

func devIdleTimeout(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	maxMin := paramInt(meta, "max_minutes", 10)
	v := atoiSafe(cfg.Device.MgmtFlags["idle-timeout"])
	f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature}, Verdict: engine.Pass}
	if v == 0 || v > maxMin {
		f.Verdict = engine.Fail
		f.Message = fmt.Sprintf("Admin idle timeout is %s; unattended sessions should log out within %d minutes.", zeroAsNever(v), maxMin)
		f.FailedFields = map[string]any{"idle-timeout": v}
	}
	return []engine.Finding{f}
}

func devFailedAttempts(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	v := atoiSafe(cfg.Device.AdminLockout["failed-attempts"])
	f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature}, Verdict: engine.Pass}
	if v == 0 || v > 5 {
		f.Verdict = engine.Fail
		f.Message = fmt.Sprintf("Failed login attempts before lockout is %s; five or fewer limits brute-force while tolerating typos.", zeroAsNever(v))
		f.FailedFields = map[string]any{"admin-lockout.failed-attempts": v}
	}
	return []engine.Finding{f}
}

func devLockoutTime(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	v := atoiSafe(cfg.Device.AdminLockout["lockout-time"])
	f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature}, Verdict: engine.Pass}
	if v < 30 {
		f.Verdict = engine.Fail
		f.Message = fmt.Sprintf("Lockout time is %d minutes; below 30, a brute-force tool just waits out the lock.", v)
		f.FailedFields = map[string]any{"admin-lockout.lockout-time": v}
	}
	return []engine.Finding{f}
}

func devAPIKeyLifetime(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	v := atoiSafe(cfg.Device.APIKeyLifetime)
	f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature}, Verdict: engine.Pass}
	if v == 0 {
		f.Verdict = engine.Fail
		f.Message = "API keys never expire; a leaked key is valid forever until manually revoked. Set a key lifetime."
		f.FailedFields = map[string]any{"api.key.lifetime": "unset (never expires)"}
	}
	return []engine.Finding{f}
}

func devPermittedIP(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature}, Verdict: engine.Pass}
	if len(cfg.Device.PermittedIPs) == 0 {
		f.Verdict = engine.Fail
		f.Message = "The management interface accepts connections from any source; restrict it to management networks with Permitted IP Addresses."
		f.FailedFields = map[string]any{"permitted-ip": []string{}}
	}
	return []engine.Finding{f}
}

func devPermittedIPBroad(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature}, Verdict: engine.Pass}
	if len(cfg.Device.PermittedIPs) == 0 {
		f.Verdict = engine.Fail
		f.Message = "No Permitted IP Addresses are configured on the management interface."
		f.FailedFields = map[string]any{"permitted-ip": []string{}}
		return []engine.Finding{f}
	}
	var broad []string
	for _, ip := range cfg.Device.PermittedIPs {
		if ip == "0.0.0.0/0" || ip == "::/0" {
			broad = append(broad, ip)
		}
	}
	if len(broad) > 0 {
		f.Verdict = engine.Fail
		f.Message = "The Permitted IP list contains an any-source entry, which defeats the restriction."
		f.FailedFields = map[string]any{"permitted-ip": broad}
	}
	return []engine.Finding{f}
}

func devMgmtEncryptedOnly(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature}, Verdict: engine.Pass}
	offenders := map[string]any{}
	svc := cfg.Device.SysFlags
	// disable-telnet / disable-http default to yes (services off) when absent.
	for _, flag := range []string{"disable-telnet", "disable-http"} {
		if v, ok := svc[flag]; ok && v != "yes" {
			offenders[flag] = v
		}
	}
	if len(offenders) > 0 {
		f.Verdict = engine.Fail
		f.Message = "Unencrypted management services (HTTP/Telnet) are enabled; credentials and sessions traverse the network in cleartext."
		f.FailedFields = offenders
	}
	return []engine.Finding{f}
}

func devFQDNRefresh(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature}, Verdict: engine.Pass}
	if v := atoiSafe(cfg.Device.SysFlags["fqdn-refresh-time"]); v > 30 {
		f.Verdict = engine.Fail
		f.Message = "FQDN objects refresh slower than every 30 seconds; policy lags behind DNS changes for FQDN-based rules."
		f.FailedFields = map[string]any{"fqdn-refresh-time": v}
	}
	return []engine.Finding{f}
}

func devTelemetry(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature}, Verdict: engine.Pass}
	// Reference-verified: a configured region counts as sharing enabled; the
	// check fails only when every telemetry setting is explicitly "no".
	t := cfg.Device.TelemetryFlags
	if len(t) > 0 {
		allNo := true
		for _, v := range t {
			if v != "no" {
				allNo = false
				break
			}
		}
		if allNo {
			f.Verdict = engine.Fail
			f.Message = "Device telemetry sharing is fully disabled; telemetry feeds the threat intelligence the subscriptions depend on."
			f.FailedFields = map[string]any{"device-telemetry": "all disabled"}
		}
	}
	return []engine.Finding{f}
}

func devSecureConn(cfg *model.Config, meta engine.CheckMeta) []engine.Finding {
	f := engine.Finding{Object: engine.ObjectRef{Section: "device", Feature: meta.Feature}, Verdict: engine.Pass}
	if !cfg.Device.SecureConnCert {
		f.Verdict = engine.Fail
		f.Message = "Secure client communication uses predefined certificates; custom certificates prevent cross-customer impersonation of management channels."
		f.FailedFields = map[string]any{"secure-conn-client.certificate": "not configured"}
	}
	return []engine.Finding{f}
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func zeroAsNever(v int) string {
	if v == 0 {
		return "unset (never)"
	}
	return fmt.Sprintf("%d minutes", v)
}
