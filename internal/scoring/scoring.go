package scoring

import (
	"fmt"
	"time"

	"lockstate/internal/collector"
	"lockstate/internal/cve"
	"lockstate/internal/detector"
	"lockstate/internal/scanner"
)

type Mode int

type Input struct {
	System *collector.SystemInfo
	Scan   *scanner.Result
	Detect *detector.Result
	CVE    *cve.Result
}

type ScoreResult struct {
	Global    int         `json:"global"` // 0-100
	Breakdown []ScoreItem `json:"breakdown"`
	Alerts    []Alert     `json:"alerts"`
}

type ScoreItem struct {
	Category string `json:"category"`
	Score    int    `json:"score"`
	Weight   int    `json:"weight"`
	Impact   int    `json:"impact"`
}

type Alert struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type Weights struct {
	Encryption  int `yaml:"encryption"`
	Updates     int `yaml:"updates"`
	Services    int `yaml:"services"`
	Credentials int `yaml:"credentials"`
	Firewall    int `yaml:"firewall"`
	Users       int `yaml:"users"`
	CVEs        int `yaml:"cves"`
	Logs        int `yaml:"logs"`
}

var defaultWeights = Weights{
	Encryption:  25,
	Updates:     20,
	Services:    15,
	Credentials: 15,
	Firewall:    10,
	Users:       8,
	CVEs:        5,
	Logs:        2,
}

func Calculate(input Input, mode Mode) *ScoreResult {
	w := defaultWeights
	// ModeQuick = 0
	if mode == 0 {
		w.CVEs = 0
		w.Logs = 0
		w.Credentials = 10
	}

	result := &ScoreResult{}
	totalWeight := 0
	totalImpact := 0

	// 1. Chiffrement
	{
		score := 100
		if input.System != nil && !input.System.Encryption.Enabled {
			score = 0
			result.Alerts = append(result.Alerts, Alert{
				Severity: "critical",
				Message:  "Aucun chiffrement disque actif — données exposées en cas de vol physique",
			})
		} else if input.System != nil && input.System.Encryption.DrivesTotal > 0 && input.System.Encryption.DrivesCount < input.System.Encryption.DrivesTotal {
			score = 50
			result.Alerts = append(result.Alerts, Alert{
				Severity: "high",
				Message:  "Chiffrement partiel : certains disques ne sont pas chiffrés",
			})
		}
		totalWeight += w.Encryption
		totalImpact += score * w.Encryption / 100
		result.Breakdown = append(result.Breakdown, ScoreItem{
			Category: "Chiffrement",
			Score:    score,
			Weight:   w.Encryption,
			Impact:   score * w.Encryption / 100,
		})
	}

	// 2. Mises à jour
	{
		score := 100
		if input.System != nil {
			// Seul le correctif le plus récent compte. Les dates absentes ou illisibles
			// (le collecteur Windows ne les renseigne pas encore) sont ignorées.
			if newest, ok := newestPatchDate(input.System.Patches); ok && time.Since(newest) > 30*24*time.Hour {
				days := time.Since(newest).Hours() / 24
				score = max(0, 100-int(days)*2)
				if score < 30 {
					result.Alerts = append(result.Alerts, Alert{
						Severity: "high",
						Message:  fmt.Sprintf("Dernière mise à jour il y a %.0f jours", days),
					})
				}
			}
		}
		totalWeight += w.Updates
		totalImpact += score * w.Updates / 100
		result.Breakdown = append(result.Breakdown, ScoreItem{
			Category: "Mises à jour",
			Score:    score,
			Weight:   w.Updates,
			Impact:   score * w.Updates / 100,
		})
	}

	// 3. Services et ports
	{
		score := 100
		if input.System != nil {
			highRiskPorts := 0
			mediumRiskPorts := 0
			for _, p := range input.System.OpenPorts {
				// Stub logic matching collector port risk logic
				risk := "low"
				switch p.Port {
				case 21, 23, 25, 135, 139, 445, 3389, 5900, 6379:
					risk = "high"
				case 22, 80, 443, 1433, 3306, 5432, 27017:
					risk = "medium"
				}

				if risk == "high" {
					highRiskPorts++
				} else if risk == "medium" {
					mediumRiskPorts++
				}
			}
			score -= highRiskPorts * 20
			score -= mediumRiskPorts * 10
			if highRiskPorts > 0 {
				result.Alerts = append(result.Alerts, Alert{
					Severity: "high",
					Message:  fmt.Sprintf("%d port(s) à haut risque ouverts (dont SMB, RDP, Telnet)", highRiskPorts),
				})
			}
		}
		score = max(0, score)
		totalWeight += w.Services
		totalImpact += score * w.Services / 100
		result.Breakdown = append(result.Breakdown, ScoreItem{
			Category: "Services exposés",
			Score:    score,
			Weight:   w.Services,
			Impact:   score * w.Services / 100,
		})
	}

	// 4. Pare-feu
	{
		score := 100
		if input.System != nil && !input.System.Firewall.Enabled {
			score = 0
			result.Alerts = append(result.Alerts, Alert{
				Severity: "critical",
				Message:  "Pare-feu désactivé — aucune protection réseau",
			})
		}
		totalWeight += w.Firewall
		totalImpact += score * w.Firewall / 100
		result.Breakdown = append(result.Breakdown, ScoreItem{
			Category: "Pare-feu",
			Score:    score,
			Weight:   w.Firewall,
			Impact:   score * w.Firewall / 100,
		})
	}

	// 5. Credentials (si scannés)
	if input.Scan != nil {
		score := 100
		criticalCount := 0
		highCount := 0
		for _, f := range input.Scan.Findings {
			if f.Risk == "critical" {
				criticalCount++
			} else if f.Risk == "high" {
				highCount++
			}
		}
		score -= criticalCount * 25
		score -= highCount * 10
		if criticalCount > 0 {
			result.Alerts = append(result.Alerts, Alert{
				Severity: "critical",
				Message:  fmt.Sprintf("%d clé(s) privée(s) ou token(s) API trouvé(s) en clair", criticalCount),
			})
		}
		if highCount > 0 {
			result.Alerts = append(result.Alerts, Alert{
				Severity: "high",
				Message:  fmt.Sprintf("%d fichier(s) contenant des mots de passe identifiés", highCount),
			})
		}
		score = max(0, score)
		totalWeight += w.Credentials
		totalImpact += score * w.Credentials / 100
		result.Breakdown = append(result.Breakdown, ScoreItem{
			Category: "Credentials",
			Score:    score,
			Weight:   w.Credentials,
			Impact:   score * w.Credentials / 100,
		})
	}

	// 6. CVE (si mode deep)
	if input.CVE != nil {
		score := 100
		for _, c := range input.CVE.Vulnerabilities {
			if c.CVSS >= 9.0 {
				score -= 20
				result.Alerts = append(result.Alerts, Alert{
					Severity: "critical",
					Message:  fmt.Sprintf("CVE-%s: %s (CVSS %.1f) — %s", c.ID, c.Software, c.CVSS, c.Description),
				})
			} else if c.CVSS >= 7.0 {
				score -= 10
			}
		}
		score = max(0, score)
		totalWeight += w.CVEs
		totalImpact += score * w.CVEs / 100
		result.Breakdown = append(result.Breakdown, ScoreItem{
			Category: "Vulnérabilités connues",
			Score:    score,
			Weight:   w.CVEs,
			Impact:   score * w.CVEs / 100,
		})
	}

	// Score global
	if totalWeight > 0 {
		result.Global = totalImpact * 100 / totalWeight
	} else {
		result.Global = 100
	}

	return result
}

// newestPatchDate retourne la date d'installation la plus récente parmi les correctifs
// dont la date est exploitable (format YYYY-MM-DD, éventuellement suivi d'une heure).
func newestPatchDate(patches []collector.PatchInfo) (time.Time, bool) {
	var newest time.Time
	found := false
	for _, p := range patches {
		if len(p.InstalledOn) < len("2006-01-02") {
			continue
		}
		t, err := time.Parse("2006-01-02", p.InstalledOn[:10])
		if err != nil {
			continue
		}
		if !found || t.After(newest) {
			newest, found = t, true
		}
	}
	return newest, found
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
