// Package parse builds the normalized model from a PAN-OS firewall
// configuration XML tree.
//
// Phase 0 scope: firewall (single- or multi-vsys) local configuration —
// security rulebase, zones, profile groups, and the device settings the seed
// checks need. Panorama configs and pushed-rulebase specifics land in a later
// phase.
package parse

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gitupcourt/open-pan-bpa/internal/model"
	"github.com/gitupcourt/open-pan-bpa/internal/xmlnode"
)

// Build normalizes a parsed <config> tree into the model.
func Build(root *xmlnode.Node) (*model.Config, error) {
	cfg := &model.Config{}

	dev := root.First("devices", "entry")
	if dev == nil {
		return nil, fmt.Errorf("config has no devices/entry — unsupported document shape")
	}

	cfg.Hostname = dev.ChildText("deviceconfig", "system", "hostname")
	parseDevice(dev, &cfg.Device)
	parseMgtConfig(root.First("mgt-config"), &cfg.Device)

	for _, vsys := range dev.Entries("vsys") {
		name := vsys.Attr("name")
		cfg.Vsys = append(cfg.Vsys, name)
		for _, e := range vsys.Entries("zone") {
			cfg.Zones = append(cfg.Zones, parseZone(e, name))
		}
		for _, e := range vsys.Entries("profile-group") {
			cfg.ProfileGroups = append(cfg.ProfileGroups, parseProfileGroup(e, name))
		}
		for _, e := range vsys.All("rulebase", "security", "rules", "entry") {
			cfg.SecurityRules = append(cfg.SecurityRules, parseSecurityRule(e, name))
		}
	}

	// Shared profile groups (firewall shared scope).
	if shared := root.First("shared"); shared != nil {
		for _, e := range shared.Entries("profile-group") {
			cfg.ProfileGroups = append(cfg.ProfileGroups, parseProfileGroup(e, "shared"))
		}
	}

	// A config with no vsys is not a firewall. Refuse loudly rather than
	// producing a near-empty "assessment" that looks like a clean result.
	if len(cfg.Vsys) == 0 {
		markers := []string{}
		for _, m := range []string{"device-group", "template", "template-stack", "log-collector"} {
			if len(dev.Entries(m)) > 0 {
				markers = append(markers, m)
			}
		}
		if len(markers) > 0 {
			return nil, fmt.Errorf("this is a Panorama/management-appliance configuration (found %s) — Panorama assessment is not supported yet; run against a firewall tech support file or config export", strings.Join(markers, ", "))
		}
		return nil, fmt.Errorf("no vsys found in configuration — unsupported document shape")
	}

	return cfg, nil
}

func yes(s string) bool { return s == "yes" }

func parseSecurityRule(e *xmlnode.Node, location string) model.SecurityRule {
	r := model.SecurityRule{
		Name:                            e.Attr("name"),
		UUID:                            e.Attr("uuid"),
		Location:                        location,
		Description:                     e.ChildText("description"),
		Action:                          e.ChildText("action"),
		Disabled:                        yes(e.ChildText("disabled")),
		RuleType:                        firstNonEmpty(e.ChildText("rule-type"), "universal"),
		From:                            e.Members("from"),
		To:                              e.Members("to"),
		Source:                          e.Members("source"),
		Destination:                     e.Members("destination"),
		SourceUser:                      e.Members("source-user"),
		Application:                     e.Members("application"),
		Service:                         e.Members("service"),
		Category:                        e.Members("category"),
		Tags:                            e.Members("tag"),
		Schedule:                        e.ChildText("schedule"),
		LogStart:                        yes(e.ChildText("log-start")),
		LogSetting:                      e.ChildText("log-setting"),
		DisableServerResponseInspection: yes(e.ChildText("option", "disable-server-response-inspection")),
	}
	// log-end defaults to yes on PAN-OS when the element is absent.
	if le := e.First("log-end"); le != nil {
		r.LogEnd = yes(le.TrimText())
	} else {
		r.LogEnd = true
	}
	if ps := e.First("profile-setting"); ps != nil {
		if g := ps.Members("group"); len(g) > 0 {
			r.ProfileGroup = g[0]
		}
		if profs := ps.First("profiles"); profs != nil {
			r.Profiles = map[string]string{}
			for _, kind := range profs.Children {
				if m := kind.Members(); len(m) > 0 {
					r.Profiles[kind.Name] = m[0]
				}
			}
		}
	}
	return r
}

func parseZone(e *xmlnode.Node, location string) model.Zone {
	z := model.Zone{
		Name:                     e.Attr("name"),
		Location:                 location,
		EnableUserIdentification: yes(e.ChildText("enable-user-identification")),
	}
	if nw := e.First("network"); nw != nil {
		z.Layer3Interfaces = nw.Members("layer3")
		z.Layer2Interfaces = nw.Members("layer2")
		z.TapInterfaces = nw.Members("tap")
		z.VirtualWireInterfaces = nw.Members("virtual-wire")
		z.ExternalInterfaces = nw.Members("external")
		z.ZoneProtectionProfile = nw.ChildText("zone-protection-profile")
		z.LogSetting = nw.ChildText("log-setting")
		z.EnablePacketBufferProt = yes(nw.ChildText("enable-packet-buffer-protection"))
	}
	if acl := e.First("user-acl"); acl != nil {
		z.UserACLInclude = acl.Members("include-list")
		z.UserACLExclude = acl.Members("exclude-list")
	}
	return z
}

func parseProfileGroup(e *xmlnode.Node, location string) model.ProfileGroup {
	g := model.ProfileGroup{
		Name:     e.Attr("name"),
		Location: location,
		Profiles: map[string]string{},
	}
	for _, kind := range e.Children {
		if m := kind.Members(); len(m) > 0 {
			g.Profiles[kind.Name] = m[0]
		}
	}
	return g
}

func parseDevice(dev *xmlnode.Node, d *model.Device) {
	sys := dev.First("deviceconfig", "system")
	if sys == nil {
		return
	}
	d.NTPPrimary = sys.ChildText("ntp-servers", "primary-ntp-server", "ntp-server-address")
	d.NTPSecondary = sys.ChildText("ntp-servers", "secondary-ntp-server", "ntp-server-address")
}

func parseMgtConfig(mgt *xmlnode.Node, d *model.Device) {
	pc := mgt.First("password-complexity")
	if pc == nil {
		return
	}
	d.PasswordComplexityEnabled = yes(pc.ChildText("enabled"))
	d.PasswordMinLength = atoi(pc.ChildText("minimum-length"))
	d.PasswordMinUppercase = atoi(pc.ChildText("minimum-uppercase-letters"))
	d.PasswordMinLowercase = atoi(pc.ChildText("minimum-lowercase-letters"))
	d.PasswordMinNumeric = atoi(pc.ChildText("minimum-numeric-letters"))
	d.PasswordMinSpecial = atoi(pc.ChildText("minimum-special-characters"))
	d.PasswordBlockUsername = yes(pc.ChildText("block-username-inclusion"))
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
