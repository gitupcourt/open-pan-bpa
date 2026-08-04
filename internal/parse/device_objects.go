package parse

import (
	"github.com/gitupcourt/open-pan-bpa/internal/model"
	"github.com/gitupcourt/open-pan-bpa/internal/xmlnode"
)

// parseDeviceObjects normalizes update schedules, HA state, server profiles,
// certificates, admin roles, auth sequences, and shared log settings.
func parseDeviceObjects(root, dev *xmlnode.Node, cfg *model.Config) {
	// Dynamic update schedules.
	cfg.UpdateSchedules = map[string]model.UpdateSchedule{}
	if us := dev.First("deviceconfig", "system", "update-schedule"); us != nil {
		for _, content := range us.Children {
			rec := content.First("recurring")
			if rec == nil {
				continue
			}
			s := model.UpdateSchedule{SyncToPeer: rec.ChildText("sync-to-peer")}
			s.Threshold = atoi(rec.ChildText("threshold"))
			for _, c := range rec.Children {
				switch c.Name {
				case "sync-to-peer", "threshold":
					continue
				default:
					s.Frequency = c.Name
					s.Action = c.ChildText("action")
					if t := atoi(c.ChildText("threshold")); t > 0 {
						s.Threshold = t
					}
				}
			}
			cfg.UpdateSchedules[content.Name] = s
		}
	}

	cfg.HAEnabled = yes(dev.ChildText("deviceconfig", "high-availability", "enabled"))

	// Server profiles + shared objects live under <shared> (and occasionally
	// per-vsys; shared covers the fleet configs seen so far).
	scopes := []struct {
		node     *xmlnode.Node
		location string
	}{{root.First("shared"), "shared"}}
	for _, vsys := range dev.Entries("vsys") {
		scopes = append(scopes, struct {
			node     *xmlnode.Node
			location string
		}{vsys, vsys.Attr("name")})
	}
	for _, scope := range scopes {
		if scope.node == nil {
			continue
		}
		sp := scope.node.First("server-profile")
		if sp != nil {
			for _, e := range sp.Entries("ldap") {
				cfg.ServerProfiles = append(cfg.ServerProfiles, model.ServerProfile{
					Name: e.Attr("name"), Location: scope.location, Kind: "ldap",
					ServerCount: len(e.Entries("server")),
					Flags: map[string]string{
						"ssl":                       e.ChildText("ssl"),
						"verify-server-certificate": e.ChildText("verify-server-certificate"),
					},
				})
			}
			for _, e := range sp.Entries("syslog") {
				p := model.ServerProfile{Name: e.Attr("name"), Location: scope.location, Kind: "syslog", ServerCount: len(e.Entries("server"))}
				for _, srv := range e.Entries("server") {
					p.Transports = append(p.Transports, srv.ChildText("transport"))
				}
				cfg.ServerProfiles = append(cfg.ServerProfiles, p)
			}
			for _, e := range sp.Entries("tacplus") {
				proto := e.ChildText("protocol")
				if proto == "" {
					if pn := e.First("protocol"); pn != nil && len(pn.Children) > 0 {
						proto = pn.Children[0].Name
					}
				}
				cfg.ServerProfiles = append(cfg.ServerProfiles, model.ServerProfile{
					Name: e.Attr("name"), Location: scope.location, Kind: "tacplus",
					ServerCount: len(e.Entries("server")),
					Flags:       map[string]string{"protocol": proto},
				})
			}
		}
		for _, e := range scope.node.Entries("certificate") {
			cfg.Certificates = append(cfg.Certificates, model.Certificate{
				Name: e.Attr("name"), Location: scope.location,
				ForwardTrust:   yes(e.ChildText("forward-trust-ca")),
				ForwardUntrust: yes(e.ChildText("forward-untrust-ca")),
			})
		}
		// The authoritative trust/untrust roles come from the ssl-decrypt
		// assignment (per-cert flags are the legacy encoding).
		if sd := scope.node.First("ssl-decrypt"); sd != nil {
			markDecryptCerts(sd, cfg)
		}
		for _, e := range scope.node.Entries("ssl-tls-service-profile") {
			cfg.SSLTLSProfiles = append(cfg.SSLTLSProfiles, model.SSLTLSProfile{
				Name: e.Attr("name"), Location: scope.location,
				MinVersion: e.ChildText("protocol-settings", "min-version"),
				MaxVersion: e.ChildText("protocol-settings", "max-version"),
			})
		}
		for _, e := range scope.node.Entries("admin-role") {
			role := e.First("role")
			cfg.AdminRoles = append(cfg.AdminRoles, model.AdminRole{
				Name:          e.Attr("name"),
				HasDeviceRole: role.First("device") != nil,
				HasVsysRole:   role.First("vsys") != nil,
			})
		}
		for _, e := range scope.node.Entries("authentication-sequence") {
			cfg.AuthSequences = append(cfg.AuthSequences, model.AuthSequence{
				Name:         e.Attr("name"),
				ProfileCount: len(e.Members("authentication-profiles")),
			})
		}
		// Shared system/config log forwarding.
		if ls := scope.node.First("log-settings"); ls != nil {
			for _, m := range ls.All("system", "match-list", "entry") {
				cfg.SystemLogMatches = append(cfg.SystemLogMatches, simpleMatch(m))
			}
			for _, m := range ls.All("config", "match-list", "entry") {
				cfg.ConfigLogMatches = append(cfg.ConfigLogMatches, simpleMatch(m))
			}
		}
	}
}

// markDecryptCerts applies ssl-decrypt forward trust/untrust certificate
// assignments (rsa + ecdsa slots) onto the certificate objects.
func markDecryptCerts(sd *xmlnode.Node, cfg *model.Config) {
	apply := func(section string, set func(*model.Certificate)) {
		n := sd.First(section)
		if n == nil {
			return
		}
		names := map[string]bool{}
		for _, c := range n.Children {
			if t := c.TrimText(); t != "" {
				names[t] = true
			}
		}
		for i := range cfg.Certificates {
			if names[cfg.Certificates[i].Name] {
				set(&cfg.Certificates[i])
			}
		}
	}
	apply("forward-trust-certificate", func(c *model.Certificate) { c.ForwardTrust = true })
	apply("forward-untrust-certificate", func(c *model.Certificate) { c.ForwardUntrust = true })
}

func simpleMatch(m *xmlnode.Node) model.SimpleLogMatch {
	dest := yes(m.ChildText("send-to-panorama")) ||
		len(m.Members("send-syslog"))+len(m.Members("send-http"))+len(m.Members("send-snmptrap"))+len(m.Members("send-email")) > 0
	return model.SimpleLogMatch{Filter: m.ChildText("filter"), HasDest: dest}
}
