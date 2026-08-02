package parse

import (
	"github.com/gitupcourt/open-pan-bpa/internal/model"
	"github.com/gitupcourt/open-pan-bpa/internal/xmlnode"
)

// parseProfiles normalizes the security profile objects the check corpus
// evaluates. scope is the containing <vsys entry> or <shared> node; location
// is the vsys name or "shared".
func parseProfiles(scope *xmlnode.Node, location string, cfg *model.Config) {
	profiles := scope.First("profiles")
	if profiles != nil {
		for _, e := range profiles.Entries("virus") {
			cfg.AntivirusProfiles = append(cfg.AntivirusProfiles, parseAntivirus(e, location))
		}
		for _, e := range profiles.Entries("file-blocking") {
			cfg.FileBlockingProfiles = append(cfg.FileBlockingProfiles, parseFileBlocking(e, location))
		}
		for _, e := range profiles.Entries("wildfire-analysis") {
			cfg.WildfireProfiles = append(cfg.WildfireProfiles, parseWildfire(e, location))
		}
		for _, e := range profiles.Entries("spyware") {
			cfg.SpywareProfiles = append(cfg.SpywareProfiles, parseSpyware(e, location))
		}
		for _, e := range profiles.Entries("vulnerability") {
			cfg.VulnerabilityProfiles = append(cfg.VulnerabilityProfiles, parseVulnerability(e, location))
		}
		for _, e := range profiles.Entries("decryption") {
			cfg.DecryptionProfiles = append(cfg.DecryptionProfiles, parseDecryption(e, location))
		}
		for _, e := range profiles.Entries("url-filtering") {
			cfg.URLFilteringProfiles = append(cfg.URLFilteringProfiles, parseURLFiltering(e, location))
		}
	}
	for _, e := range scope.All("log-settings", "profiles", "entry") {
		cfg.LogForwardingProfiles = append(cfg.LogForwardingProfiles, parseLogForwarding(e, location))
	}
}

func parseAntivirus(e *xmlnode.Node, location string) model.AntivirusProfile {
	p := model.AntivirusProfile{
		Name:          e.Attr("name"),
		Location:      location,
		PacketCapture: yes(e.ChildText("packet-capture")),
		MlavEngines:   map[string]string{},
		AppExceptions: map[string]string{},
	}
	for _, d := range e.Entries("decoder") {
		p.Decoders = append(p.Decoders, model.AVDecoder{
			Name:           d.Attr("name"),
			Action:         d.ChildText("action"),
			WildfireAction: d.ChildText("wildfire-action"),
			MlavAction:     d.ChildText("mlav-action"),
		})
	}
	for _, m := range e.Entries("mlav-engine-filebased-enabled") {
		p.MlavEngines[m.Attr("name")] = m.ChildText("mlav-policy-action")
	}
	for _, a := range e.Entries("application") {
		p.AppExceptions[a.Attr("name")] = a.ChildText("action")
	}
	for _, tx := range e.Entries("threat-exception") {
		p.ThreatExceptions = append(p.ThreatExceptions, tx.Attr("name"))
	}
	return p
}

func parseFileBlocking(e *xmlnode.Node, location string) model.FileBlockingProfile {
	p := model.FileBlockingProfile{Name: e.Attr("name"), Location: location}
	for _, r := range e.All("rules", "entry") {
		p.Rules = append(p.Rules, model.FileBlockingRule{
			Name:         r.Attr("name"),
			Applications: r.Members("application"),
			FileTypes:    r.Members("file-type"),
			Direction:    r.ChildText("direction"),
			Action:       r.ChildText("action"),
		})
	}
	return p
}

func parseWildfire(e *xmlnode.Node, location string) model.WildfireProfile {
	p := model.WildfireProfile{
		Name:                e.Attr("name"),
		Location:            location,
		CloudInlineAnalysis: yes(e.ChildText("cloud-inline-analysis")),
	}
	for _, r := range e.All("rules", "entry") {
		p.Rules = append(p.Rules, model.WildfireRule{
			Name:         r.Attr("name"),
			Applications: r.Members("application"),
			FileTypes:    r.Members("file-type"),
			Direction:    r.ChildText("direction"),
			Analysis:     r.ChildText("analysis"),
		})
	}
	return p
}

// flagMap flattens an element's children into name -> trimmed text.
func flagMap(n *xmlnode.Node) map[string]string {
	if n == nil {
		return nil
	}
	m := make(map[string]string, len(n.Children))
	for _, c := range n.Children {
		m[c.Name] = c.TrimText()
	}
	return m
}

func parseDecryption(e *xmlnode.Node, location string) model.DecryptionProfile {
	return model.DecryptionProfile{
		Name:             e.Attr("name"),
		Location:         location,
		ForwardProxy:     flagMap(e.First("ssl-forward-proxy")),
		InboundProxy:     flagMap(e.First("ssl-inbound-proxy")),
		NoProxy:          flagMap(e.First("ssl-no-proxy")),
		SSHProxy:         flagMap(e.First("ssh-proxy")),
		ProtocolSettings: flagMap(e.First("ssl-protocol-settings")),
	}
}

func parseURLFiltering(e *xmlnode.Node, location string) model.URLFilteringProfile {
	p := model.URLFilteringProfile{
		Name:             e.Attr("name"),
		Location:         location,
		Block:            e.Members("block"),
		Alert:            e.Members("alert"),
		Allow:            e.Members("allow"),
		Continue:         e.Members("continue"),
		LogContainerOnly: logContainerDefault(e),
		CloudInlineCat:   yes(e.ChildText("cloud-inline-cat")),
		MlavEngines:      map[string]string{},
	}
	if ce := e.First("credential-enforcement"); ce != nil {
		p.CredBlock = ce.Members("block")
		p.CredAllow = ce.Members("allow")
		if m := ce.First("mode"); m != nil && len(m.Children) > 0 {
			p.CredMode = m.Children[0].Name
		}
	}
	for _, m := range e.Entries("mlav-engine-urlbased-enabled") {
		p.MlavEngines[m.Attr("name")] = m.ChildText("mlav-policy-action")
	}
	return p
}

// logContainerDefault: log-container-page-only defaults to yes when absent.
func logContainerDefault(e *xmlnode.Node) bool {
	if n := e.First("log-container-page-only"); n != nil {
		return yes(n.TrimText())
	}
	return true
}

// actionName returns the action verb for rules that encode the action as a
// child element name (<action><reset-both/></action>).
func actionName(rule *xmlnode.Node) string {
	a := rule.First("action")
	if a == nil || len(a.Children) == 0 {
		return ""
	}
	return a.Children[0].Name
}

func parseThreatRule(r *xmlnode.Node) model.ThreatRule {
	return model.ThreatRule{
		Name:          r.Attr("name"),
		Severities:    r.Members("severity"),
		Action:        actionName(r),
		PacketCapture: r.ChildText("packet-capture"),
		Host:          r.ChildText("host"),
	}
}

func parseSpyware(e *xmlnode.Node, location string) model.SpywareProfile {
	p := model.SpywareProfile{
		Name:                e.Attr("name"),
		Location:            location,
		CloudInlineAnalysis: yes(e.ChildText("cloud-inline-analysis")),
		MicaEngines:         map[string]string{},
	}
	for _, r := range e.All("rules", "entry") {
		p.Rules = append(p.Rules, parseThreatRule(r))
	}
	for _, tx := range e.Entries("threat-exception") {
		p.ThreatExceptions = append(p.ThreatExceptions, tx.Attr("name"))
	}
	for _, m := range e.Entries("mica-engine-spyware-enabled") {
		p.MicaEngines[m.Attr("name")] = m.ChildText("inline-policy-action")
	}
	for _, c := range e.All("botnet-domains", "dns-security-categories", "entry") {
		p.DNSCategories = append(p.DNSCategories, model.DNSCategory{
			Name:          c.Attr("name"),
			Action:        c.ChildText("action"),
			LogLevel:      c.ChildText("log-level"),
			PacketCapture: c.ChildText("packet-capture"),
		})
	}
	return p
}

func parseVulnerability(e *xmlnode.Node, location string) model.VulnerabilityProfile {
	p := model.VulnerabilityProfile{
		Name:                e.Attr("name"),
		Location:            location,
		CloudInlineAnalysis: yes(e.ChildText("cloud-inline-analysis")),
		MicaEngines:         map[string]string{},
	}
	for _, r := range e.All("rules", "entry") {
		p.Rules = append(p.Rules, parseThreatRule(r))
	}
	for _, tx := range e.Entries("threat-exception") {
		p.ThreatExceptions = append(p.ThreatExceptions, tx.Attr("name"))
	}
	for _, m := range e.Entries("mica-engine-vulnerability-enabled") {
		p.MicaEngines[m.Attr("name")] = m.ChildText("inline-policy-action")
	}
	return p
}

func parseLogForwarding(e *xmlnode.Node, location string) model.LogForwardingProfile {
	p := model.LogForwardingProfile{Name: e.Attr("name"), Location: location}
	for _, m := range e.Entries("match-list") {
		p.Matches = append(p.Matches, model.LogForwardingMatch{
			Name:           m.Attr("name"),
			LogType:        m.ChildText("log-type"),
			SendToPanorama: yes(m.ChildText("send-to-panorama")),
			SendSyslog:     m.Members("send-syslog"),
			SendHTTP:       m.Members("send-http"),
			SendSNMP:       m.Members("send-snmptrap"),
			SendEmail:      m.Members("send-email"),
		})
	}
	return p
}
