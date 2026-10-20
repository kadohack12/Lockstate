package cve

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// ── Schéma de la base ──

const schemaSQL = `
CREATE TABLE IF NOT EXISTS cves (
	cve_id              TEXT PRIMARY KEY,
	software_name       TEXT NOT NULL,
	affected_version    TEXT NOT NULL DEFAULT '*',
	affected_version_end TEXT NOT NULL DEFAULT '',
	cvss_score          REAL NOT NULL DEFAULT 0.0,
	description         TEXT NOT NULL DEFAULT '',
	reference           TEXT NOT NULL DEFAULT '',
	published_date      TEXT NOT NULL DEFAULT '',
	last_modified       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_software_name ON cves(LOWER(software_name));
CREATE INDEX IF NOT EXISTS idx_cvss ON cves(cvss_score DESC);

CREATE TABLE IF NOT EXISTS metadata (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`

// ── Structures NVD API v2.0 ──

type nvdResponse struct {
	ResultsPerPage  int       `json:"resultsPerPage"`
	StartIndex      int       `json:"startIndex"`
	TotalResults    int       `json:"totalResults"`
	Vulnerabilities []nvdVuln `json:"vulnerabilities"`
}

type nvdVuln struct {
	CVE struct {
		ID           string `json:"id"`
		Published    string `json:"published"`
		LastModified string `json:"lastModified"`
		Descriptions []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"descriptions"`
		Metrics struct {
			CvssMetricV31 []struct {
				CvssData struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"cvssData"`
			} `json:"cvssMetricV31"`
			CvssMetricV2 []struct {
				CvssData struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"cvssData"`
			} `json:"cvssMetricV2"`
		} `json:"metrics"`
		Configurations []struct {
			Nodes []struct {
				CpeMatch []struct {
					Criteria              string `json:"criteria"`
					VersionStartIncluding string `json:"versionStartIncluding"`
					VersionEndIncluding   string `json:"versionEndIncluding"`
					VersionEndExcluding   string `json:"versionEndExcluding"`
				} `json:"cpeMatch"`
			} `json:"nodes"`
		} `json:"configurations"`
		References []struct {
			URL string `json:"url"`
		} `json:"references"`
	} `json:"cve"`
}

// ── InitDatabase crée la base et le schéma si nécessaire ──

func InitDatabase() error {
	path := dbPath()

	// Créer le répertoire data/ si absent
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("création répertoire data : %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return fmt.Errorf("ouverture base : %w", err)
	}
	defer db.Close()

	_, err = db.Exec(schemaSQL)
	if err != nil {
		return fmt.Errorf("création schéma : %w", err)
	}

	log.Printf("Base CVE initialisée : %s", path)
	return nil
}

// ── UpdateDatabase télécharge les CVE depuis l'API NVD et les insère ──

func UpdateDatabase() error {
	// 1. Initialiser la base si nécessaire
	if err := InitDatabase(); err != nil {
		return err
	}

	path := dbPath()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()

	// 2. Déterminer la date de dernière mise à jour
	lastModified := getLastModified(db)
	log.Printf("Dernière mise à jour : %s", lastModified)

	// 3. Télécharger les CVE pertinentes (logiciels qu'on surveille)
	keywords := []string{
		"openssh", "openssl", "apache", "nginx", "mysql", "mariadb",
		"postgresql", "mongodb", "redis", "docker", "chromium",
		"firefox", "java", "python", "nodejs", "linux_kernel",
		"sudo", "polkit", "systemd", "samba", "putty", "filezilla",
		"7-zip", "vlc", "libreoffice", "thunderbird",
		"git", "virtualbox", "vmware", "teamviewer", "anydesk",
		"wireshark", "notepad++",
	}

	totalInserted := 0
	for _, kw := range keywords {
		count, err := fetchAndStore(db, kw, lastModified)
		if err != nil {
			log.Printf("  ⚠ Erreur pour %s : %v", kw, err)
			continue
		}
		if count > 0 {
			log.Printf("  ✓ %s : %d CVE importées", kw, count)
		}
		totalInserted += count

		// Respect du rate-limit NVD : max 5 requêtes / 30 secondes (sans API key)
		time.Sleep(6500 * time.Millisecond)
	}

	// 4. Mettre à jour le timestamp
	if err := setLastModified(db, time.Now().UTC().Format(time.RFC3339)); err != nil {
		log.Printf("  ⚠ horodatage de mise à jour non enregistré : %v", err)
	}

	log.Printf("Mise à jour terminée : %d CVE importées au total", totalInserted)
	return nil
}

// fetchAndStore interroge l'API NVD pour un mot-clé et insère les résultats
func fetchAndStore(db *sql.DB, keyword, lastModified string) (int, error) {
	// Construction de l'URL NVD API v2.0
	url := fmt.Sprintf(
		"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=100",
		keyword,
	)

	// Si on a une date de dernière mise à jour, ne récupérer que les nouvelles
	if lastModified != "" {
		url += fmt.Sprintf("&lastModStartDate=%s&lastModEndDate=%s",
			lastModified,
			time.Now().UTC().Format("2006-01-02T15:04:05.000"),
		)
	}

	// Requête HTTP
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0, fmt.Errorf("requête NVD : %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		return 0, fmt.Errorf("rate-limit NVD atteint (403) — réessayez dans 30 secondes")
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("NVD HTTP %d : %s", resp.StatusCode, string(body[:min(len(body), 200)]))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	// Parser la réponse JSON
	var nvdResp nvdResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return 0, fmt.Errorf("parsing JSON NVD : %w", err)
	}

	// Insérer les CVE dans la base
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}

	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO cves 
		(cve_id, software_name, affected_version, affected_version_end, cvss_score, description, reference, published_date, last_modified)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		_ = tx.Rollback() // l'erreur d'origine est plus utile que celle du rollback
		return 0, err
	}
	defer stmt.Close()

	count := 0
	for _, v := range nvdResp.Vulnerabilities {
		cveID := v.CVE.ID

		// Extraire la description (préférence français, sinon anglais)
		desc := ""
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "fr" {
				desc = d.Value
				break
			}
			if d.Lang == "en" {
				desc = d.Value
			}
		}

		// Extraire le score CVSS (v3.1 en priorité, fallback v2)
		cvss := 0.0
		if len(v.CVE.Metrics.CvssMetricV31) > 0 {
			cvss = v.CVE.Metrics.CvssMetricV31[0].CvssData.BaseScore
		} else if len(v.CVE.Metrics.CvssMetricV2) > 0 {
			cvss = v.CVE.Metrics.CvssMetricV2[0].CvssData.BaseScore
		}

		// On ne garde que les CVE avec un score significatif
		if cvss < 4.0 {
			continue
		}

		// Extraire les versions affectées depuis les CPE
		affectedVersion := "*"
		affectedVersionEnd := ""
		softwareName := keyword

		for _, cfg := range v.CVE.Configurations {
			for _, node := range cfg.Nodes {
				for _, cpe := range node.CpeMatch {
					// CPE format: cpe:2.3:a:vendor:product:version:...
					parts := strings.Split(cpe.Criteria, ":")
					if len(parts) >= 6 {
						softwareName = parts[4] // Nom du produit dans le CPE
						if parts[5] != "*" && parts[5] != "-" {
							affectedVersion = parts[5]
						}
					}
					if cpe.VersionEndIncluding != "" {
						affectedVersionEnd = cpe.VersionEndIncluding
					}
					if cpe.VersionEndExcluding != "" {
						affectedVersionEnd = cpe.VersionEndExcluding
					}
				}
			}
		}

		// Référence (première URL)
		ref := ""
		if len(v.CVE.References) > 0 {
			ref = v.CVE.References[0].URL
		}

		_, err := stmt.Exec(
			cveID, softwareName, affectedVersion, affectedVersionEnd,
			cvss, desc, ref,
			v.CVE.Published, v.CVE.LastModified,
		)
		if err != nil {
			continue
		}
		count++
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return count, nil
}

// ── Helpers metadata ──

func getLastModified(db *sql.DB) string {
	var val string
	err := db.QueryRow("SELECT value FROM metadata WHERE key = 'last_modified'").Scan(&val)
	if err != nil {
		return ""
	}
	return val
}

func setLastModified(db *sql.DB, val string) error {
	_, err := db.Exec("INSERT OR REPLACE INTO metadata (key, value) VALUES ('last_modified', ?)", val)
	return err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
