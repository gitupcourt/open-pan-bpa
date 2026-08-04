package parse

import (
	"os"
	"strings"
	"testing"

	"github.com/gitupcourt/open-pan-bpa/internal/xmlnode"
)

func loadMini(t *testing.T) *xmlnode.Node {
	t.Helper()
	f, err := os.Open("testdata/mini-config.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	root, err := xmlnode.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestPanoramaConfigParsed(t *testing.T) {
	xml := `<config version="11.1.0">
	  <readonly><devices><entry name="localhost.localdomain"><device-group>
	    <entry name="child-dg"><parent-dg>parent-dg</parent-dg></entry>
	  </device-group></entry></devices></readonly>
	  <shared>
	    <pre-rulebase><security><rules>
	      <entry name="shared-pre"><action>deny</action></entry>
	    </rules></security></pre-rulebase>
	  </shared>
	  <devices><entry name="localhost.localdomain">
	    <deviceconfig><system><hostname>PANO-1</hostname></system></deviceconfig>
	    <device-group>
	      <entry name="parent-dg">
	        <pre-rulebase><security><rules>
	          <entry name="parent-rule"><action>allow</action></entry>
	        </rules></security></pre-rulebase>
	      </entry>
	      <entry name="child-dg">
	        <parent-dg>parent-dg</parent-dg>
	        <devices><entry name="007000000001"/></devices>
	        <post-rulebase><security><rules>
	          <entry name="child-post"><action>allow</action></entry>
	        </rules></security></post-rulebase>
	      </entry>
	    </device-group>
	    <template><entry name="tmpl-1"><config><devices><entry name="localhost.localdomain">
	      <vsys><entry name="vsys1"><zone><entry name="tz"><network><layer3><member>eth1/1</member></layer3></network></entry></zone></entry></vsys>
	    </entry></devices></config></entry></template>
	    <template-stack><entry name="stack-1">
	      <templates><member>tmpl-1</member></templates>
	      <devices><entry name="007000000001"/></devices>
	    </entry></template-stack>
	  </entry></devices>
	</config>`
	root, err := xmlnode.Parse(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	if !IsPanorama(root) {
		t.Fatal("config should be detected as Panorama")
	}
	cfg, err := BuildAuto(root)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Panorama == nil {
		t.Fatal("Panorama info not populated")
	}
	if cfg.Hostname != "PANO-1" {
		t.Errorf("hostname = %q", cfg.Hostname)
	}
	if len(cfg.Panorama.DeviceGroups) != 2 {
		t.Fatalf("device groups = %d, want 2", len(cfg.Panorama.DeviceGroups))
	}
	// Hierarchy comes from the readonly subtree.
	if got := cfg.Panorama.Ancestors("child-dg"); len(got) != 1 || got[0] != "parent-dg" {
		t.Errorf("ancestors of child-dg = %v, want [parent-dg]", got)
	}
	// Pre, post, and shared rules all land in the evaluated rulebase.
	names := map[string]string{}
	for _, r := range cfg.SecurityRules {
		names[r.Name] = r.Location
	}
	for rule, loc := range map[string]string{
		"parent-rule": "parent-dg", "child-post": "child-dg", "shared-pre": "shared",
	} {
		if names[rule] != loc {
			t.Errorf("rule %q location = %q, want %q", rule, names[rule], loc)
		}
	}
	if len(cfg.Zones) != 1 || cfg.Zones[0].Location != "tmpl-1/vsys1" {
		t.Errorf("template zone not attributed: %+v", cfg.Zones)
	}
	if len(cfg.Panorama.TemplateStacks) != 1 || len(cfg.Panorama.TemplateStacks[0].Templates) != 1 {
		t.Errorf("template stack not parsed: %+v", cfg.Panorama.TemplateStacks)
	}
}

func TestBuildMiniConfig(t *testing.T) {
	cfg, err := Build(loadMini(t))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hostname != "TESTFW-01" {
		t.Errorf("hostname = %q", cfg.Hostname)
	}
	if len(cfg.Vsys) != 1 || cfg.Vsys[0] != "vsys1" {
		t.Errorf("vsys = %v", cfg.Vsys)
	}
	if len(cfg.SecurityRules) != 6 {
		t.Fatalf("rules = %d, want 6", len(cfg.SecurityRules))
	}
	if len(cfg.Zones) != 3 {
		t.Errorf("zones = %d, want 3", len(cfg.Zones))
	}
	if len(cfg.ProfileGroups) != 2 {
		t.Errorf("profile groups = %d, want 2", len(cfg.ProfileGroups))
	}

	good := cfg.SecurityRules[0]
	if good.Name != "good-rule" || good.ProfileGroup != "strict-group" || !good.LogEnd || good.LogSetting != "lfp-default" {
		t.Errorf("good-rule parsed wrong: %+v", good)
	}
	naked := cfg.SecurityRules[1]
	if naked.LogEnd {
		t.Error("naked-allow log-end should be false")
	}
	indiv := cfg.SecurityRules[3]
	if indiv.Profiles["virus"] != "strict-av" || indiv.Profiles["spyware"] != "strict-as" {
		t.Errorf("individual profiles parsed wrong: %+v", indiv.Profiles)
	}
	disabled := cfg.SecurityRules[5]
	if !disabled.Disabled {
		t.Error("disabled-bad-rule should be disabled")
	}
	// log-end absent → defaults to true
	if !disabled.LogEnd {
		t.Error("absent log-end should default true")
	}

	if cfg.Device.NTPPrimary != "192.0.2.10" || cfg.Device.NTPSecondary != "" {
		t.Errorf("ntp parsed wrong: %+v", cfg.Device)
	}
	if !cfg.Device.PasswordComplexityEnabled || cfg.Device.PasswordMinNumeric != 0 {
		t.Errorf("password complexity parsed wrong: %+v", cfg.Device)
	}
}
