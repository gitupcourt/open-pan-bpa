package parse

import (
	"strings"

	"github.com/gitupcourt/open-pan-bpa/internal/model"
	"github.com/gitupcourt/open-pan-bpa/internal/xmlnode"
)

// parseNetworkObjects normalizes HA, zone protection, interface management,
// GlobalProtect gateways, and crypto profiles.
func parseNetworkObjects(dev *xmlnode.Node, cfg *model.Config) {
	if ha := dev.First("deviceconfig", "high-availability"); ha != nil && yes(ha.ChildText("enabled")) {
		cfg.HA = parseHA(ha)
	}
	network := dev.First("network")
	if network == nil {
		return
	}
	profiles := network.First("profiles")
	if profiles != nil {
		for _, e := range profiles.Entries("zone-protection-profile") {
			p := model.ZoneProtectionProfile{
				Name: e.Attr("name"), Location: "vsys1",
				ScanEntries: len(e.Entries("scan")),
				PacketFlags: leafMap(e),
			}
			cfg.ZoneProtections = append(cfg.ZoneProtections, p)
		}
		for _, e := range profiles.Entries("interface-management-profile") {
			cfg.InterfaceMgmt = append(cfg.InterfaceMgmt, model.InterfaceMgmtProfile{
				Name: e.Attr("name"), Location: "vsys1",
				HTTP:   e.ChildText("http"),
				Telnet: e.ChildText("telnet"),
			})
		}
	}
	for _, e := range network.All("ike", "crypto-profiles", "ike-crypto-profiles", "entry") {
		cfg.IKEProfiles = append(cfg.IKEProfiles, parseCrypto(e))
	}
	for _, e := range network.All("ike", "crypto-profiles", "ipsec-crypto-profiles", "entry") {
		cfg.IPSecProfiles = append(cfg.IPSecProfiles, parseCrypto(e))
	}
	for _, e := range network.All("global-protect", "global-protect-gateway", "entry") {
		cfg.GPGateways = append(cfg.GPGateways, parseGPGateway(e))
	}
}

func parseHA(ha *xmlnode.Node) model.HAConfig {
	h := model.HAConfig{}
	iface := ha.First("interface")
	if iface != nil {
		h.HA1Port = iface.ChildText("ha1", "port")
		h.HA1BackupPort = iface.ChildText("ha1-backup", "port")
		h.HA1Encryption = iface.ChildText("ha1", "encryption", "enabled")
		h.HA3Configured = iface.First("ha3", "port") != nil
	}
	group := ha.First("group")
	if group == nil {
		return h
	}
	h.ConfigSyncDisabled = group.ChildText("configuration-synchronization", "enabled") == "no"
	h.PeerIPBackup = group.ChildText("peer-ip-backup")
	h.PassiveLinkState = group.ChildText("mode", "active-passive", "passive-link-state")
	if aa := group.First("mode", "active-active"); aa != nil {
		h.ActiveActive = true
		h.SessionOwnerFirstPkt = aa.First("session-owner-selection", "first-packet") != nil
	}
	if timers := group.First("election-option", "timers"); timers != nil && len(timers.Children) > 0 {
		h.TimersMode = timers.Children[0].Name
	}
	h.HeartbeatBackup = group.ChildText("election-option", "heartbeat-backup")
	h.StateSyncDisabled = group.ChildText("state-synchronization", "enabled") == "no"
	h.HA2KeepAlive = group.ChildText("state-synchronization", "ha2-keep-alive", "enabled")
	if mon := group.First("monitoring"); mon != nil {
		h.LinkMonDisabled = mon.ChildText("link-monitoring", "enabled") == "no"
		h.LinkGroups = len(mon.All("link-monitoring", "link-group", "entry"))
		h.PathMonDisabled = mon.ChildText("path-monitoring", "enabled") == "no"
		pg := mon.First("path-monitoring", "path-group")
		if pg != nil {
			for _, kind := range pg.Children {
				h.PathGroups += len(kind.Children)
			}
		}
	}
	return h
}

func parseCrypto(e *xmlnode.Node) model.CryptoProfile {
	p := model.CryptoProfile{Name: e.Attr("name"), Location: "vsys1"}
	if ake := e.First("ake"); ake != nil {
		for _, round := range ake.Children {
			p.AKE = append(p.AKE, round.TrimText())
		}
	}
	return p
}

func parseGPGateway(e *xmlnode.Node) model.GPGateway {
	g := model.GPGateway{
		// Vendor reports strip the tunnel-mode "-N" suffix from gateway names.
		Name:     strings.TrimSuffix(e.Attr("name"), "-N"),
		Location: "vsys1",
	}
	g.TLSProfile = findChildText(e, "ssl-tls-service-profile")
	for _, ca := range e.All("client-auth", "entry") {
		if ca.ChildText("authentication-profile") != "" {
			g.HasClientAuth = true
		}
	}
	g.HasCertProfile = e.ChildText("certificate-profile") != ""
	for _, tc := range e.All("remote-user-tunnel-configs", "entry") {
		g.TunnelConfigs++
		for _, m := range tc.Members("split-tunneling", "access-route") {
			if m == "0.0.0.0/0" || m == "::/0" {
				g.TunnelsFullAccess++
				break
			}
		}
	}
	if sat := e.First("satellite-config"); sat != nil {
		g.HasSatellite = true
		g.SatelliteReplay = findChildText(e, "anti-replay")
	}
	return g
}

// findChildText searches the subtree depth-first for the first element with
// the given name and returns its text.
func findChildText(n *xmlnode.Node, name string) string {
	if n == nil {
		return ""
	}
	for _, c := range n.Children {
		if c.Name == name {
			return c.TrimText()
		}
		if v := findChildText(c, name); v != "" {
			return v
		}
	}
	return ""
}
