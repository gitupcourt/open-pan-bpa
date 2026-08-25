package xmlnode

import (
	"strings"
	"testing"
)

func parse(t *testing.T, s string) *Node {
	t.Helper()
	n, err := Parse(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestOverlayStackComposition(t *testing.T) {
	// Higher-priority template: defines banner + one syslog profile.
	hi := parse(t, `<config>
	  <devices><entry name="localhost.localdomain">
	    <deviceconfig><system><login-banner>corp</login-banner></system></deviceconfig>
	  </entry></devices>
	  <shared><log-settings><syslog><entry name="corp-siem"><server><entry name="a"><transport>SSL</transport></entry></server></entry></syslog></log-settings></shared>
	</config>`)
	// Lower-priority template: different banner (must lose), ntp (must be
	// inherited), an extra syslog profile (must union), and a member list.
	lo := parse(t, `<config>
	  <devices><entry name="localhost.localdomain">
	    <deviceconfig><system>
	      <login-banner>global</login-banner>
	      <ntp-servers><primary-ntp-server><ntp-server-address>10.0.0.1</ntp-server-address></primary-ntp-server></ntp-servers>
	    </system></deviceconfig>
	  </entry></devices>
	  <shared><log-settings><syslog><entry name="global-siem"><server/></entry></syslog>
	    <system><match-list><entry name="crit"><filter>x</filter><send-syslog><member>global-siem</member></send-syslog></entry></match-list></system>
	  </log-settings></shared>
	</config>`)

	merged := &Node{Name: "config"}
	Overlay(merged, hi)
	Overlay(merged, lo)

	sys := merged.First("devices", "entry", "deviceconfig", "system")
	if got := sys.ChildText("login-banner"); got != "corp" {
		t.Fatalf("banner = %q, want higher-priority \"corp\"", got)
	}
	if got := sys.ChildText("ntp-servers", "primary-ntp-server", "ntp-server-address"); got != "10.0.0.1" {
		t.Fatalf("ntp not inherited from lower template: %q", got)
	}
	slogs := merged.All("shared", "log-settings", "syslog", "entry")
	if len(slogs) != 2 {
		t.Fatalf("syslog entries = %d, want union of 2", len(slogs))
	}
	if got := merged.First("shared", "log-settings", "syslog", "entry").ChildText("server", "entry", "transport"); got != "SSL" {
		t.Fatalf("higher-priority profile content lost: transport = %q", got)
	}
	if ml := merged.All("shared", "log-settings", "system", "match-list", "entry"); len(ml) != 1 {
		t.Fatalf("match-list not inherited: %d entries", len(ml))
	}
}

func TestOverlayRepeatedGroupBaseWins(t *testing.T) {
	base := parse(t, `<a><list><member>x</member><member>y</member></list></a>`)
	add := parse(t, `<a><list><member>z</member></list></a>`)
	Overlay(base, add)
	if got := base.Members("list"); len(got) != 2 || got[0] != "x" {
		t.Fatalf("base member group must win atomically: %v", got)
	}
}

func TestOverlayRepeatedGroupInheritedWhole(t *testing.T) {
	base := parse(t, `<a><other>v</other></a>`)
	add := parse(t, `<a><list><member>x</member><member>y</member></list></a>`)
	Overlay(base, add)
	if got := base.Members("list"); len(got) != 2 {
		t.Fatalf("whole repeated group must be inherited: %v", got)
	}
}
