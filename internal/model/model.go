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

	AntivirusProfiles     []AntivirusProfile
	FileBlockingProfiles  []FileBlockingProfile
	WildfireProfiles      []WildfireProfile
	LogForwardingProfiles []LogForwardingProfile
	SpywareProfiles       []SpywareProfile
	VulnerabilityProfiles []VulnerabilityProfile
	DecryptionProfiles    []DecryptionProfile

	// LicenseInfoAvailable is true when the input carried license state
	// (tech support files do; bare config XML exports cannot).
	LicenseInfoAvailable bool
	Licenses             []License
}

// AVDecoder is one protocol decoder row in an Antivirus profile. Empty action
// strings mean the profile inherits the content default for that decoder.
type AVDecoder struct {
	Name           string
	Action         string
	WildfireAction string
	MlavAction     string
}

// AVDecoderNames are the seven standard Antivirus protocol decoders.
var AVDecoderNames = []string{"ftp", "http", "http2", "imap", "pop3", "smb", "smtp"}

// AVDecodersDefaultResetBoth are decoders whose content-default action is
// already reset-both, so an explicit "default" is acceptable there.
var AVDecodersDefaultResetBoth = map[string]bool{"ftp": true, "http": true, "http2": true, "smb": true}

// AntivirusProfile is a normalized Antivirus (virus) profile.
type AntivirusProfile struct {
	Name             string
	Location         string
	Decoders         []AVDecoder
	MlavEngines      map[string]string // model name -> mlav-policy-action
	AppExceptions    map[string]string // application name -> action
	ThreatExceptions []string
	PacketCapture    bool
}

// Decoder returns the decoder row by name, with zero value when absent.
func (p AntivirusProfile) Decoder(name string) AVDecoder {
	for _, d := range p.Decoders {
		if d.Name == name {
			return d
		}
	}
	return AVDecoder{Name: name}
}

// FileBlockingRule is one rule in a File Blocking profile.
type FileBlockingRule struct {
	Name         string
	Applications []string
	FileTypes    []string
	Direction    string
	Action       string
}

// FileBlockingProfile is a normalized File Blocking profile.
type FileBlockingProfile struct {
	Name     string
	Location string
	Rules    []FileBlockingRule
}

// WildfireRule is one rule in a WildFire Analysis profile.
type WildfireRule struct {
	Name         string
	Applications []string
	FileTypes    []string
	Direction    string
	Analysis     string
}

// WildfireProfile is a normalized WildFire Analysis profile.
type WildfireProfile struct {
	Name                string
	Location            string
	Rules               []WildfireRule
	CloudInlineAnalysis bool
}

// LogForwardingMatch is one match-list entry in a Log Forwarding profile.
type LogForwardingMatch struct {
	Name           string
	LogType        string
	SendToPanorama bool
	SendSyslog     []string
	SendHTTP       []string
	SendSNMP       []string
	SendEmail      []string
}

// HasDestination reports whether the match forwards anywhere at all.
func (m LogForwardingMatch) HasDestination() bool {
	return m.SendToPanorama || len(m.SendSyslog)+len(m.SendHTTP)+len(m.SendSNMP)+len(m.SendEmail) > 0
}

// LogForwardingProfile is a normalized Log Forwarding profile.
type LogForwardingProfile struct {
	Name     string
	Location string
	Matches  []LogForwardingMatch
}

// ThreatRule is one severity rule in an Anti-Spyware or Vulnerability
// Protection profile. Action is the rule's action verb (the XML encodes it as
// a child element name, e.g. <action><reset-both/></action>).
type ThreatRule struct {
	Name          string
	Severities    []string
	Action        string
	PacketCapture string // disable | single-packet | extended-capture
	Host          string // vulnerability rules only: client | server | any
}

// BlockingThreatActions are rule actions that actually stop the session.
var BlockingThreatActions = map[string]bool{
	"reset-both": true, "drop": true, "reset-client": true, "reset-server": true, "block-ip": true,
}

// DNSCategory is one DNS Security category row in an Anti-Spyware profile's
// botnet-domains configuration.
type DNSCategory struct {
	Name          string
	Action        string
	LogLevel      string
	PacketCapture string
}

// SpywareProfile is a normalized Anti-Spyware profile.
type SpywareProfile struct {
	Name                string
	Location            string
	Rules               []ThreatRule
	ThreatExceptions    []string
	CloudInlineAnalysis bool
	MicaEngines         map[string]string // engine name -> inline-policy-action
	DNSCategories       []DNSCategory
}

// VulnerabilityProfile is a normalized Vulnerability Protection profile.
type VulnerabilityProfile struct {
	Name                string
	Location            string
	Rules               []ThreatRule
	ThreatExceptions    []string
	CloudInlineAnalysis bool
	MicaEngines         map[string]string
}

// DecryptionProfile is a normalized Decryption profile. Each section is a
// flat flag map (XML element name -> text); absent flags fall back to
// per-flag content defaults encoded in the checks.
type DecryptionProfile struct {
	Name             string
	Location         string
	ForwardProxy     map[string]string // ssl-forward-proxy
	InboundProxy     map[string]string // ssl-inbound-proxy
	NoProxy          map[string]string // ssl-no-proxy
	SSHProxy         map[string]string // ssh-proxy
	ProtocolSettings map[string]string // ssl-protocol-settings
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
