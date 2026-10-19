package report

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"lockstate/internal/collector"
	"lockstate/internal/scoring"
)

//go:embed templates/report.html
var reportTemplate string

type ReportData struct {
	Hostname         string
	OS               string
	Date             string
	Score            int
	ScoreLabel       string
	ScoreClass       string
	Alerts           []scoring.Alert
	Breakdown        []scoring.ScoreItem
	System           *collector.SystemInfo
	Uptime           string
	FirewallStatus   string
	EncryptionStatus string
	UserCount        int
}

func Generate(sysInfo *collector.SystemInfo, score *scoring.ScoreResult, outputPath string) error {
	ext := filepath.Ext(outputPath)

	switch ext {
	case ".html":
		return generateHTML(sysInfo, score, outputPath)
	case ".json":
		return generateJSON(sysInfo, score, outputPath)
	default:
		return generateHTML(sysInfo, score, outputPath)
	}
}

func generateHTML(sysInfo *collector.SystemInfo, score *scoring.ScoreResult, outputPath string) error {
	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return err
	}

	fwStatus := "Désactivé"
	if sysInfo.Firewall.Enabled {
		fwStatus = "Activé"
	}

	encStatus := "Désactivé"
	if sysInfo.Encryption.Enabled {
		encStatus = "Activé"
	}

	scoreClass := "score-low"
	scoreLabel := "Risque Faible"
	if score.Global < 40 {
		scoreClass = "score-critical"
		scoreLabel = "Risque Critique"
	} else if score.Global < 70 {
		scoreClass = "score-high"
		scoreLabel = "Risque Élevé"
	} else if score.Global < 90 {
		scoreClass = "score-medium"
		scoreLabel = "Risque Modéré"
	}

	data := ReportData{
		Hostname:         sysInfo.Hostname,
		OS:               sysInfo.OSVersion,
		Date:             time.Now().Format("2006-01-02 15:04"),
		Score:            score.Global,
		ScoreLabel:       scoreLabel,
		ScoreClass:       scoreClass,
		Alerts:           score.Alerts,
		Breakdown:        score.Breakdown,
		System:           sysInfo,
		Uptime:           sysInfo.Uptime.String(),
		FirewallStatus:   fwStatus,
		EncryptionStatus: encStatus,
		UserCount:        len(sysInfo.Users),
	}

	// Ensure target directory exists
	os.MkdirAll(filepath.Dir(outputPath), 0755)

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

// generateJSON génère un rapport au format JSON
func generateJSON(sysInfo *collector.SystemInfo, score *scoring.ScoreResult, outputPath string) error {
	// Ensure target directory exists
	os.MkdirAll(filepath.Dir(outputPath), 0755)

	type JSONReport struct {
		Hostname         string                `json:"hostname"`
		OS               string                `json:"os"`
		Date             string                `json:"date"`
		Score            int                   `json:"score"`
		ScoreLabel       string                `json:"score_label"`
		Alerts           []scoring.Alert       `json:"alerts"`
		Breakdown        []scoring.ScoreItem   `json:"breakdown"`
		System           *collector.SystemInfo `json:"system"`
		FirewallStatus   string                `json:"firewall_status"`
		EncryptionStatus string                `json:"encryption_status"`
		UserCount        int                   `json:"user_count"`
	}

	fwStatus := "Disabled"
	if sysInfo.Firewall.Enabled {
		fwStatus = "Enabled"
	}

	encStatus := "Disabled"
	if sysInfo.Encryption.Enabled {
		encStatus = "Enabled"
	}

	scoreLabel := "Low Risk"
	if score.Global < 40 {
		scoreLabel = "Critical Risk"
	} else if score.Global < 70 {
		scoreLabel = "High Risk"
	} else if score.Global < 90 {
		scoreLabel = "Medium Risk"
	}

	report := JSONReport{
		Hostname:         sysInfo.Hostname,
		OS:               sysInfo.OSVersion,
		Date:             time.Now().Format("2006-01-02 15:04"),
		Score:            score.Global,
		ScoreLabel:       scoreLabel,
		Alerts:           score.Alerts,
		Breakdown:        score.Breakdown,
		System:           sysInfo,
		FirewallStatus:   fwStatus,
		EncryptionStatus: encStatus,
		UserCount:        len(sysInfo.Users),
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0644)
}
