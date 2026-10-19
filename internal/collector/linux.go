//go:build linux

package collector

import (
	"bufio"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func collectLinux(info *SystemInfo) error {
	hostname, _ := os.Hostname()
	info.Hostname = hostname

	info.OSVersion = getLinuxOSRelease()
	info.KernelVersion = getLinuxKernel()
	info.Uptime = getLinuxUptime()
	info.Users = getLinuxUsers()
	info.Admins = getLinuxAdmins()

	info.OpenPorts = getLinuxPorts()
	info.Services = getLinuxServices()

	info.Firewall = getLinuxFirewall()
	info.Encryption = getLinuxEncryption()
	info.Patches = getLinuxPatches()
	info.Software = getLinuxSoftware()

	return nil
}

func getLinuxOSRelease() string {
	data, err := ioutil.ReadFile("/etc/os-release")
	if err != nil {
		return "unknown"
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
		}
	}
	return "unknown"
}

func getLinuxKernel() string {
	data, err := ioutil.ReadFile("/proc/version")
	if err != nil {
		return "unknown"
	}
	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		return fields[2]
	}
	return "unknown"
}

func getLinuxUptime() time.Duration {
	data, err := ioutil.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0
	}
	seconds, _ := strconv.ParseFloat(fields[0], 64)
	return time.Duration(seconds) * time.Second
}

func getLinuxUsers() []UserInfo {
	passwd, err := ioutil.ReadFile("/etc/passwd")
	if err != nil {
		return nil
	}

	var users []UserInfo
	scanner := bufio.NewScanner(strings.NewReader(string(passwd)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		username := parts[0]
		uid, _ := strconv.Atoi(parts[2])
		shell := parts[6]

		if uid < 1000 && uid != 0 {
			continue
		}

		hasShell := !strings.Contains(shell, "nologin") && !strings.Contains(shell, "false")

		users = append(users, UserInfo{
			Name:    username,
			Enabled: hasShell,
		})
	}

	return users
}

func getLinuxAdmins() []string {
	var admins []string

	for _, group := range []string{"sudo", "wheel", "admin"} {
		data, err := ioutil.ReadFile("/etc/group")
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, group+":") {
				parts := strings.Split(line, ":")
				if len(parts) >= 4 && parts[3] != "" {
					admins = append(admins, strings.Split(parts[3], ",")...)
				}
			}
		}
	}

	return admins
}

// getServiceByPort retourne le service associé au port
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

// classifyPortRisk classe le risque d'un port
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

// getLinuxServices récupère les services systemd actifs
func getLinuxServices() []ServiceInfo {
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--active", "--no-pager")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var services []ServiceInfo
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.HasSuffix(fields[0], ".service") {
			services = append(services, ServiceInfo{
				Name:   strings.TrimSuffix(fields[0], ".service"),
				Status: "running",
			})
		}
	}
	return services
}

func getLinuxPorts() []PortInfo {
	tcpData, err := ioutil.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil
	}

	var ports []PortInfo
	scanner := bufio.NewScanner(strings.NewReader(string(tcpData)))
	scanner.Scan() // skip header
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		localAddr := fields[1]
		state := fields[3]

		if state != "0A" {
			continue
		}

		addrParts := strings.Split(localAddr, ":")
		if len(addrParts) < 2 {
			continue
		}

		portHex := addrParts[len(addrParts)-1]
		port, err := strconv.ParseInt(portHex, 16, 64)
		if err != nil {
			continue
		}

		service := getServiceByPort(int(port))
		risk := classifyPortRisk(int(port))

		ports = append(ports, PortInfo{
			Port:    int(port),
			Proto:   "tcp",
			Service: service,
			Risk:    risk,
		})
	}

	return ports
}

func getLinuxFirewall() FirewallState {
	state := FirewallState{}

	cmd := exec.Command("iptables", "-L", "-n", "--line-numbers")
	output, err := cmd.Output()
	if err == nil {
		state.Enabled = true
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "Chain INPUT") || strings.Contains(line, "Chain FORWARD") || strings.Contains(line, "Chain OUTPUT") {
				state.RulesIn++
			}
		}
	}

	data, err := ioutil.ReadFile("/etc/ufw/ufw.conf")
	if err == nil {
		if strings.Contains(string(data), "ENABLED=yes") {
			state.Enabled = true
			state.Profiles = append(state.Profiles, "ufw")
		}
	}

	return state
}

func getLinuxEncryption() EncryptionInfo {
	info := EncryptionInfo{Type: "luks"}

	data, err := ioutil.ReadFile("/etc/crypttab")
	if err == nil && strings.TrimSpace(string(data)) != "" {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			parts := strings.Split(line, " ")
			if len(parts) >= 1 && parts[0] != "" && !strings.HasPrefix(parts[0], "#") {
				info.DrivesTotal++
				if _, err := os.Stat("/dev/mapper/" + parts[0]); err == nil {
					info.Enabled = true
				}
			}
		}
	}

	return info
}

func getLinuxPatches() []PatchInfo {
	var patches []PatchInfo

	data, err := ioutil.ReadFile("/var/log/apt/history.log")
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		var lastUpgrade string
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "Start-Date:") {
				lastUpgrade = strings.TrimPrefix(line, "Start-Date: ")
			}
		}
		if lastUpgrade != "" {
			patches = append(patches, PatchInfo{
				ID:          "last-upgrade",
				Description: "Dernière mise à jour APT",
				InstalledOn: strings.TrimSpace(lastUpgrade),
			})
		}
	}

	return patches
}

func getLinuxSoftware() []SoftwareInfo {
	var software []SoftwareInfo

	cmd := exec.Command("dpkg-query", "-W", "-f", "${Package}\t${Version}\n")
	output, err := cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.Split(line, "\t")
			if len(parts) < 2 {
				continue
			}
			name := parts[0]
			version := parts[1]

			if !isRelevantLinuxSoftware(name) {
				continue
			}

			software = append(software, SoftwareInfo{
				Name:    name,
				Version: version,
			})
		}
		return software
	}

	cmd = exec.Command("rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\n")
	output, err = cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.Split(line, "\t")
			if len(parts) < 2 {
				continue
			}
			name := parts[0]
			version := parts[1]

			if !isRelevantLinuxSoftware(name) {
				continue
			}

			software = append(software, SoftwareInfo{
				Name:    name,
				Version: version,
			})
		}
	}

	return software
}

func isRelevantLinuxSoftware(name string) bool {
	keywords := []string{
		"openssh", "ssh", "apache2", "nginx", "mysql", "mariadb",
		"postgresql", "mongodb", "redis", "docker", "containerd",
		"python", "nodejs", "npm", "openjdk", "default-jdk",
		"firefox", "chromium", "thunderbird", "libreoffice",
		"openssl", "libssl", "bash", "sudo", "polkit",
		"systemd", "kernel", "linux-image",
	}

	nameLower := strings.ToLower(name)
	for _, kw := range keywords {
		if strings.Contains(nameLower, kw) {
			return true
		}
	}
	return false
}
