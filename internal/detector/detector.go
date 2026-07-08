package detector

import (
	"fmt"

	"lockstate/internal/collector"
	"lockstate/internal/scanner"
)

// Result contient les résultats de l'analyse de vulnérabilités
type Result struct {
	Findings []Finding `json:"findings"`
}

// Finding représente une vulnérabilité détectée par le moteur interne
type Finding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Status      string `json:"status"`
	Remediation string `json:"remediation"`
}

// Analyze exécute l'ensemble des règles de détection sur les données collectées.
// Le paramètre mode contrôle la profondeur d'analyse (0=quick, 1=standard, 2=deep).
func Analyze(sysInfo *collector.SystemInfo, scanResult *scanner.Result, mode int) *Result {
	result := &Result{}

	if sysInfo == nil {
		return result
	}

	// ── Règles de détection internes ──

	// Règle 1 : Pare-feu désactivé
	if !sysInfo.Firewall.Enabled {
		result.Findings = append(result.Findings, Finding{
			ID:          "FW-001",
			Title:       "Pare-feu désactivé",
			Description: "Le pare-feu du système est désactivé, exposant la machine au trafic réseau non filtré.",
			Severity:    "critical",
			Category:    "Firewall",
			Status:      "Failed",
			Remediation: "Activer le pare-feu via les paramètres système ou via la commande appropriée (ufw enable / netsh advfirewall set allprofiles state on).",
		})
	}

	// Règle 2 : Chiffrement disque absent
	if !sysInfo.Encryption.Enabled {
		result.Findings = append(result.Findings, Finding{
			ID:          "ENC-001",
			Title:       "Chiffrement disque absent",
			Description: "Aucun mécanisme de chiffrement de disque n'est actif. Les données sont lisibles en clair en cas de vol physique.",
			Severity:    "critical",
			Category:    "Encryption",
			Status:      "Failed",
			Remediation: "Activer BitLocker (Windows) ou LUKS (Linux) sur tous les volumes contenant des données sensibles.",
		})
	}

	// Règle 3 : Ports à haut risque ouverts
	highRiskPorts := map[int]string{
		21:   "FTP",
		23:   "Telnet",
		135:  "RPC",
		139:  "NetBIOS",
		445:  "SMB",
		3389: "RDP",
		5900: "VNC",
		6379: "Redis",
	}
	for _, p := range sysInfo.OpenPorts {
		if svcName, ok := highRiskPorts[p.Port]; ok {
			result.Findings = append(result.Findings, Finding{
				ID:          "PORT-" + svcName,
				Title:       "Port à haut risque ouvert : " + svcName,
				Description: fmt.Sprintf("Le port %d (%s) est en écoute. Ce service est fréquemment ciblé par les attaquants.", p.Port, svcName),
				Severity:    "high",
				Category:    "Services",
				Status:      "Failed",
				Remediation: "Fermer le port ou restreindre l'accès via le pare-feu aux adresses IP autorisées uniquement.",
			})
		}
	}

	// Règle 4 : Utilisateurs admin actifs (mode standard+)
	if mode >= 1 {
		for _, u := range sysInfo.Users {
			if u.IsAdmin && u.Enabled {
				result.Findings = append(result.Findings, Finding{
					ID:          "USR-ADMIN-" + u.Name,
					Title:       "Compte administrateur actif : " + u.Name,
					Description: fmt.Sprintf("Le compte %s possède des privilèges administrateur.", u.Name),
					Severity:    "medium",
					Category:    "Users",
					Status:      "Info",
					Remediation: "S'assurer que ce compte est légitime et protégé par un mot de passe fort + MFA.",
				})
			}
		}
	}

	// Règle 5 : Credentials en clair trouvés par le scanner
	if scanResult != nil {
		for _, f := range scanResult.Findings {
			severity := "high"
			if f.Risk == "critical" {
				severity = "critical"
			}
			result.Findings = append(result.Findings, Finding{
				ID:          "CRED-" + f.PatternName,
				Title:       "Secret en clair détecté : " + f.PatternName,
				Description: fmt.Sprintf("Un secret potentiel a été trouvé dans %s (ligne %d).", f.FilePath, f.LineNumber),
				Severity:    severity,
				Category:    "Credentials",
				Status:      "Failed",
				Remediation: "Déplacer les secrets dans un gestionnaire de secrets (Vault, 1Password, etc.) et supprimer les fichiers en clair.",
			})
		}
	}

	// Règle 6 : Chiffrement partiel (mode deep)
	if mode >= 2 && sysInfo.Encryption.DrivesTotal > 0 && sysInfo.Encryption.DrivesCount < sysInfo.Encryption.DrivesTotal {
		result.Findings = append(result.Findings, Finding{
			ID:          "ENC-002",
			Title:       "Chiffrement disque partiel",
			Description: fmt.Sprintf("Seulement %d/%d volumes sont chiffrés.", sysInfo.Encryption.DrivesCount, sysInfo.Encryption.DrivesTotal),
			Severity:    "high",
			Category:    "Encryption",
			Status:      "Failed",
			Remediation: "Étendre le chiffrement à tous les volumes de stockage.",
		})
	}

	return result
}
