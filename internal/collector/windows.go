//go:build windows

package collector

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func collectWindows(info *SystemInfo) error {
	// Hostname
	hostname, _ := os.Hostname()
	info.Hostname = hostname

	// OS Version via RtlGetVersion (plus fiable que GetVersionEx)
	info.OSVersion = getWindowsVersion()

	// Kernel
	info.KernelVersion = getWindowsKernel()

	// Uptime
	info.Uptime = getUptime()

	// Utilisateurs
	info.Users = getWindowsUsers()

	// Administrateurs
	info.Admins = getWindowsAdmins()

	// Services et ports
	info.OpenPorts = getWindowsPorts()
	info.Services = getWindowsServices()

	// Pare-feu
	info.Firewall = getWindowsFirewall()

	// Chiffrement (BitLocker)
	info.Encryption = getWindowsEncryption()

	// Correctifs
	info.Patches = getWindowsPatches()

	// Logiciels
	info.Software = getWindowsSoftware()

	return nil
}

func getWindowsVersion() string {
	// Lecture dans le registre
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		registry.QUERY_VALUE)
	if err != nil {
		return "unknown"
	}
	defer k.Close()

	productName, _, _ := k.GetStringValue("ProductName")
	releaseID, _, _ := k.GetStringValue("ReleaseId")
	currentBuild, _, _ := k.GetStringValue("CurrentBuild")

	return fmt.Sprintf("%s %s (build %s)", productName, releaseID, currentBuild)
}

func getWindowsKernel() string {
	// RtlGetVersion (x/sys) retourne la version réelle de l'OS, sans passer par les manifestes.
	v := windows.RtlGetVersion()
	return fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}

func getUptime() time.Duration {
	// GetTickCount64 via syscall
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getTickCount64 := kernel32.NewProc("GetTickCount64")
	ret, _, _ := getTickCount64.Call()
	return time.Duration(ret) * time.Millisecond
}

// getWindowsUsers récupère la liste des utilisateurs locaux
func getWindowsUsers() []UserInfo {
	cmd := exec.Command("net", "user")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var users []UserInfo
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "---") {
			continue
		}
		users = append(users, UserInfo{
			Name:    line,
			Enabled: true,
		})
	}
	return users
}

// getWindowsAdmins récupère les administrateurs du système
func getWindowsAdmins() []string {
	cmd := exec.Command("net", "localgroup", "Administrators")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var admins []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.Contains(line, "---") && !strings.Contains(line, "completed successfully") {
			admins = append(admins, line)
		}
	}
	return admins
}

// getWindowsServices récupère les services Windows
func getWindowsServices() []ServiceInfo {
	cmd := exec.Command("tasklist", "/svc")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var services []ServiceInfo
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "Image Name") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			services = append(services, ServiceInfo{
				Name:   fields[0],
				Status: "running",
			})
		}
	}
	return services
}

// getWindowsFirewall récupère l'état du pare-feu Windows
func getWindowsFirewall() FirewallState {
	cmd := exec.Command("netsh", "advfirewall", "show", "allprofiles")
	output, err := cmd.Output()
	if err != nil {
		return FirewallState{Enabled: false}
	}

	outputStr := string(output)
	enabled := strings.Contains(outputStr, "State\t\t\t\tON") || strings.Contains(outputStr, "State ON")
	return FirewallState{
		Enabled: enabled,
	}
}

// getWindowsPatches récupère la liste des correctifs installés
func getWindowsPatches() []PatchInfo {
	cmd := exec.Command("wmic", "qfe", "list", "brief")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var patches []PatchInfo
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "HotFixID") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			patches = append(patches, PatchInfo{
				ID: fields[0],
			})
		}
	}
	return patches
}

func getServiceByPort(port int) string {
	highRiskServices := map[int]string{
		21:   "FTP",
		23:   "Telnet",
		135:  "RPC",
		139:  "NetBIOS",
		445:  "SMB",
		3389: "RDP",
		5900: "VNC",
		6379: "Redis",
		22:   "SSH",
		80:   "HTTP",
		443:  "HTTPS",
		1433: "MSSQL",
		3306: "MySQL",
		5432: "PostgreSQL",
	}
	if svc, ok := highRiskServices[port]; ok {
		return svc
	}
	return ""
}

func getWindowsPorts() []PortInfo {
	output, err := exec.Command("netstat", "-ano", "-p", "TCP").Output()
	if err != nil {
		return nil
	}

	var ports []PortInfo
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// On cherche les lignes avec LISTEN
		if !strings.Contains(line, "LISTEN") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Format : TCP    0.0.0.0:445    0.0.0.0:0    LISTEN    4
		proto := fields[0]
		addrPort := fields[1]

		parts := strings.Split(addrPort, ":")
		if len(parts) < 2 {
			continue
		}

		portStr := parts[len(parts)-1]

		port := 0
		fmt.Sscanf(portStr, "%d", &port)
		if port == 0 {
			continue
		}

		service := getServiceByPort(port)
		risk := classifyPortRisk(port)

		ports = append(ports, PortInfo{
			Port:    port,
			Proto:   proto,
			Service: service,
			Risk:    risk,
		})
	}

	return ports
}

func classifyPortRisk(port int) string {
	highRisk := map[int]bool{
		21: true, 23: true, 25: true, 135: true, 139: true, 445: true, 3389: true, 5900: true, 6379: true,
	}
	mediumRisk := map[int]bool{
		22: true, 80: true, 443: true, 1433: true, 3306: true, 5432: true, 27017: true,
	}

	if highRisk[port] {
		return "high"
	}
	if mediumRisk[port] {
		return "medium"
	}
	return "low"
}

func getWindowsEncryption() EncryptionInfo {
	cmd := exec.Command("manage-bde", "-status")
	output, err := cmd.Output()
	if err != nil {
		return EncryptionInfo{Enabled: false, Type: "unknown"}
	}

	info := EncryptionInfo{Type: "bitlocker"}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Fully Encrypted") || strings.Contains(line, "Protection On") {
			info.Enabled = true
		}
		if strings.Contains(line, "Drive") || strings.Contains(line, "Volume") {
			info.DrivesTotal++
		}
	}

	return info
}

func getWindowsSoftware() []SoftwareInfo {
	paths := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	}

	var software []SoftwareInfo
	seen := make(map[string]bool)

	for _, path := range paths {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		defer k.Close()

		subKeys, err := k.ReadSubKeyNames(-1)
		if err != nil {
			continue
		}

		for _, subKey := range subKeys {
			sk, err := registry.OpenKey(registry.LOCAL_MACHINE, path+`\`+subKey, registry.QUERY_VALUE)
			if err != nil {
				continue
			}

			name, _, _ := sk.GetStringValue("DisplayName")
			version, _, _ := sk.GetStringValue("DisplayVersion")
			vendor, _, _ := sk.GetStringValue("Publisher")
			sk.Close()

			if name == "" || seen[name] {
				continue
			}
			seen[name] = true

			if !isRelevantSoftware(name) {
				continue
			}

			software = append(software, SoftwareInfo{
				Name:    name,
				Version: version,
				Vendor:  vendor,
			})
		}
	}

	return software
}

func isRelevantSoftware(name string) bool {
	keywords := []string{
		"Chrome", "Firefox", "Edge", "Opera", "Brave",
		"Adobe", "Acrobat", "Reader",
		"Java", "JDK", "JRE",
		"7-Zip", "WinRAR", "WinZip",
		"Office", "Word", "Excel", "PowerPoint", "Outlook",
		"VLC", "Python", "Node.js", "Git",
		"TeamViewer", "AnyDesk", "VNC",
		"OpenVPN", "WireGuard", "NordVPN", "ExpressVPN",
		"VirtualBox", "VMware", "Docker",
		"Notepad++", "Sublime", "VS Code", "IntelliJ",
		"FileZilla", "WinSCP", "Putty",
	}

	nameLower := strings.ToLower(name)
	for _, kw := range keywords {
		if strings.Contains(nameLower, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}
