// Package model defines the normalized configuration model the check engine
// evaluates. It is a deliberate projection of the PAN-OS XML schema: flat,
// explicit, and stable across PAN-OS versions, so check logic never touches
// raw XML shapes.
package model

import "time"

// Config is the normalized firewall configuration, plus device state parsed
// from a tech support file's CLI transcript when available.
type Config struct {
	Hostname      string
	Vsys          []string
	SecurityRules []SecurityRule
	Zones         []Zone
	ProfileGroups []ProfileGroup
	Device        Device

	// LicenseInfoAvailable is true when the input carried license state
	// (tech support files do; bare config XML exports cannot).
	LicenseInfoAvailable bool
	Licenses             []License
}

// License is one entry from the device's license inventory.
type License struct {
	Feature     string
	Description string
	Expired     bool
	Never       bool      // perpetual: no expiry date
	Expires     time.Time // zero when Never
}

// SecurityRule is one security policy rule, normalized.
type SecurityRule struct {
	Name        string
	UUID        string
	Location    string // vsys name or "shared"
	Description string
	Action      string
	Disabled    bool
	RuleType    string
	From        []string
	To          []string
	Source      []string
	Destination []string
	SourceUser  []string
	Application []string
	Service     []string
	Category    []string
	Tags        []string
	Schedule    string
	LogStart    bool
	LogEnd      bool
	LogSetting  string

	// Profile attachment: either a group reference or individual profiles.
	ProfileGroup string
	Profiles     map[string]string // profile kind -> profile name

	DisableServerResponseInspection bool
}

// Profile kind keys used in SecurityRule.Profiles.
const (
	ProfVirus         = "virus"
	ProfSpyware       = "spyware"
	ProfVulnerability = "vulnerability"
	ProfURLFiltering  = "url-filtering"
	ProfFileBlocking  = "file-blocking"
	ProfWildfire      = "wildfire-analysis"
	ProfDataFiltering = "data-filtering"
)

// CoreThreatProfiles are the profile kinds whose absence on an allow rule
// means traffic passes with no threat inspection.
var CoreThreatProfiles = []string{ProfVirus, ProfSpyware, ProfVulnerability}

// Zone is one zone in one vsys.
type Zone struct {
	Name                     string
	Location                 string
	Layer3Interfaces         []string
	Layer2Interfaces         []string
	TapInterfaces            []string
	VirtualWireInterfaces    []string
	ExternalInterfaces       []string
	ZoneProtectionProfile    string
	LogSetting               string
	EnableUserIdentification bool
	EnablePacketBufferProt   bool
	UserACLInclude           []string
	UserACLExclude           []string
}

// HasInterfaces reports whether the zone has any interface members.
func (z Zone) HasInterfaces() bool {
	return len(z.Layer3Interfaces)+len(z.Layer2Interfaces)+len(z.TapInterfaces)+
		len(z.VirtualWireInterfaces)+len(z.ExternalInterfaces) > 0
}

// ProfileGroup is a security profile group object.
type ProfileGroup struct {
	Name     string
	Location string
	Profiles map[string]string // profile kind -> profile name
}

// Device holds device-wide (deviceconfig / mgt-config) settings the checks
// need.
type Device struct {
	NTPPrimary   string
	NTPSecondary string

	PasswordComplexityEnabled bool
	PasswordMinLength         int
	PasswordMinUppercase      int
	PasswordMinLowercase      int
	PasswordMinNumeric        int
	PasswordMinSpecial        int
	PasswordBlockUsername     bool
}
