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
