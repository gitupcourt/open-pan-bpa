package parse

import (
	"github.com/gitupcourt/open-pan-bpa/internal/model"
	"github.com/gitupcourt/open-pan-bpa/internal/xmlnode"
)

// BuildAuto normalizes either a firewall or a Panorama configuration,
// dispatching on the document shape.
func BuildAuto(root *xmlnode.Node) (*model.Config, error) {
	if IsPanorama(root) {
		return BuildPanorama(root)
	}
	return Build(root)
}

// IsPanorama reports whether the config document is a Panorama/management
// appliance configuration rather than a firewall's.
func IsPanorama(root *xmlnode.Node) bool {
	dev := root.First("devices", "entry")
	if dev == nil {
		return false
	}
	for _, m := range []string{"device-group", "template", "template-stack", "log-collector"} {
		if len(dev.Entries(m)) > 0 {
			return true
		}
	}
	return false
}

// BuildPanorama normalizes a Panorama configuration. Policy objects are
// attributed to device groups; shared objects and templates supply the
// device-scope configuration that gets pushed to firewalls.
//
// The device-group hierarchy lives in /config/readonly (not in the device
// group entries themselves) — a long-standing trap for naive parsers.
func BuildPanorama(root *xmlnode.Node) (*model.Config, error) {
	cfg := &model.Config{Panorama: &model.PanoramaInfo{}}

	dev := root.First("devices", "entry")
	if dev == nil {
		return nil, errNoDevices
	}
	cfg.Hostname = dev.ChildText("deviceconfig", "system", "hostname")
	parseDevice(dev, &cfg.Device)
	parseMgtConfig(root.First("mgt-config"), &cfg.Device)
	parseDeviceObjects(root, dev, cfg)
	parseNetworkObjects(dev, cfg)

	parents := readonlyParents(root)

	for _, dg := range dev.Entries("device-group") {
		name := dg.Attr("name")
		g := model.DeviceGroup{
			Name:    name,
			Parent:  parents[name],
			Devices: entryNames(dg.Entries("devices")),
		}
		for _, e := range dg.All("pre-rulebase", "security", "rules", "entry") {
			g.PreRules = append(g.PreRules, parseSecurityRule(e, name))
		}
		for _, e := range dg.All("post-rulebase", "security", "rules", "entry") {
			g.PostRules = append(g.PostRules, parseSecurityRule(e, name))
		}
		for _, e := range dg.All("post-rulebase", "default-security-rules", "rules", "entry") {
			g.DefaultRules = append(g.DefaultRules, parseSecurityRule(e, name))
		}
		for _, e := range dg.All("pre-rulebase", "decryption", "rules", "entry") {
			g.PreDecryption = append(g.PreDecryption, parseDecryptionRule(e, name))
		}
		// Objects defined in the device group are evaluated like vsys objects.
		parseProfiles(dg, name, cfg)
		for _, e := range dg.Entries("profile-group") {
			cfg.ProfileGroups = append(cfg.ProfileGroups, parseProfileGroup(e, name))
		}

		cfg.SecurityRules = append(cfg.SecurityRules, g.PreRules...)
		cfg.SecurityRules = append(cfg.SecurityRules, g.PostRules...)
		cfg.DefaultRules = append(cfg.DefaultRules, g.DefaultRules...)
		cfg.DecryptionRules = append(cfg.DecryptionRules, g.PreDecryption...)
		cfg.Panorama.DeviceGroups = append(cfg.Panorama.DeviceGroups, g)
	}

	// Shared pre/post rulebases apply above and below every device group.
	if shared := root.First("shared"); shared != nil {
		for _, path := range [][]string{{"pre-rulebase"}, {"post-rulebase"}} {
			for _, e := range shared.All(append(path, "security", "rules", "entry")...) {
				cfg.SecurityRules = append(cfg.SecurityRules, parseSecurityRule(e, "shared"))
			}
			for _, e := range shared.All(append(path, "decryption", "rules", "entry")...) {
				cfg.DecryptionRules = append(cfg.DecryptionRules, parseDecryptionRule(e, "shared"))
			}
		}
		for _, e := range shared.All("post-rulebase", "default-security-rules", "rules", "entry") {
			cfg.DefaultRules = append(cfg.DefaultRules, parseSecurityRule(e, "shared"))
		}
	}

	// Templates carry the device-scope config pushed to firewalls; each holds
	// a nested firewall-shaped <config> tree.
	for _, tmpl := range dev.Entries("template") {
		name := tmpl.Attr("name")
		cfg.Panorama.Templates = append(cfg.Panorama.Templates, name)
		tdev := tmpl.First("config", "devices", "entry")
		if tdev == nil {
			continue
		}
		for _, vsys := range tdev.Entries("vsys") {
			vname := name + "/" + vsys.Attr("name")
			for _, e := range vsys.Entries("zone") {
				cfg.Zones = append(cfg.Zones, parseZone(e, vname))
			}
			parseProfiles(vsys, vname, cfg)
		}
		parseNetworkObjects(tdev, cfg)
	}

	for _, st := range dev.Entries("template-stack") {
		cfg.Panorama.TemplateStacks = append(cfg.Panorama.TemplateStacks, model.TemplateStack{
			Name:      st.Attr("name"),
			Templates: st.Members("templates"),
			Devices:   entryNames(st.Entries("devices")),
		})
	}

	return cfg, nil
}

// readonlyParents extracts device-group parent relationships from the
// /config/readonly subtree.
func readonlyParents(root *xmlnode.Node) map[string]string {
	out := map[string]string{}
	ro := root.First("readonly", "devices", "entry")
	if ro == nil {
		return out
	}
	for _, dg := range ro.Entries("device-group") {
		if p := dg.ChildText("parent-dg"); p != "" {
			out[dg.Attr("name")] = p
		}
	}
	return out
}

func entryNames(nodes []*xmlnode.Node) []string {
	var out []string
	for _, n := range nodes {
		out = append(out, n.Attr("name"))
	}
	return out
}
