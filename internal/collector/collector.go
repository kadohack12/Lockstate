package collector

import (
	"fmt"
	"time"
)

// SystemInfo regroupe toutes les données collectées sur la machine
type SystemInfo struct {
	Hostname      string         `json:"hostname"`
	OS            string         `json:"os"`
	OSVersion     string         `json:"os_version"`
	KernelVersion string         `json:"kernel_version"`
	Uptime        time.Duration  `json:"uptime"`
	Users         []UserInfo     `json:"users"`
	Admins        []string       `json:"admins"`
	Services      []ServiceInfo  `json:"services"`
	OpenPorts     []PortInfo     `json:"open_ports"`
	Firewall      FirewallState  `json:"firewall"`
	Encryption    EncryptionInfo `json:"encryption"`
	Patches       []PatchInfo    `json:"patches"`
	Software      []SoftwareInfo `json:"software"`
}

type UserInfo struct {
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	LastLogon string `json:"last_logon"`
	IsAdmin   bool   `json:"is_admin"`
}

type ServiceInfo struct {
	Name   string `json:"name"`
	Port   int    `json:"port,omitempty"`
	Proto  string `json:"proto,omitempty"`
	Status string `json:"status"` // running, stopped
	Risk   string `json:"risk"`   // none, low, medium, high
}

type PortInfo struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Process string `json:"process,omitempty"`
	Service string `json:"service,omitempty"`
	Risk    string `json:"risk,omitempty"` // low, medium, high
}

type FirewallState struct {
	Enabled  bool     `json:"enabled"`
	Profiles []string `json:"profiles"`
	RulesIn  int      `json:"rules_inbound"`
	RulesOut int      `json:"rules_outbound"`
}

type EncryptionInfo struct {
	Enabled     bool   `json:"enabled"`
	Type        string `json:"type"` // bitlocker, luks, filevault, none
	DrivesCount int    `json:"drives_count"`
	DrivesTotal int    `json:"drives_total"`
}

type PatchInfo struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	InstalledOn string `json:"installed_on"`
	Severity    string `json:"severity"`
}

type SoftwareInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Vendor  string `json:"vendor"`
}

// Collect est l'unique point d'entrée. goos est le nom de l'OS (runtime.GOOS), reporté
// dans SystemInfo.OS. L'implémentation est choisie à la compilation par les build tags
// (voir platform_linux.go, platform_windows.go, platform_other.go) : chaque binaire ne
// contient que le collecteur de son propre OS.
func Collect(goos string) (*SystemInfo, error) {
	info := &SystemInfo{
		OS: goos,
	}

	if err := collectPlatform(info); err != nil {
		return nil, fmt.Errorf("collecte système : %w", err)
	}

	return info, nil
}
