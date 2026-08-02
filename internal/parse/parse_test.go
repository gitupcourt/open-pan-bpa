package parse

import (
	"os"
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
