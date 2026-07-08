package cve

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"lockstate/internal/collector"

	_ "modernc.org/sqlite" // Pilote SQLite pur Go — pas de CGO requis
)

// Vulnerability représente une CVE connue associée à un logiciel installé
type Vulnerability struct {
	ID          string  `json:"id"`
	Software    string  `json:"software"`
	Version     string  `json:"version"`
	CVSS        float64 `json:"cvss"`
	Description string  `json:"description"`
	Reference   string  `json:"reference"`
}

// Result contient l'ensemble des CVE trouvées
type Result struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	TotalChecked    int             `json:"total_checked"`
}

// dbPath retourne le chemin vers la base SQLite.
// On cherche d'abord à côté de l'exécutable, puis dans le répertoire courant.
func dbPath() string {
	// 1. À côté de l'exécutable
	exe, err := os.Executable()
	if err == nil {
		p := filepath.Join(filepath.Dir(exe), "data", "cve.db")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// 2. Répertoire courant
	return filepath.Join("data", "cve.db")
}

// Lookup interroge la base SQLite locale pour trouver les CVE
// correspondant aux logiciels installés sur la machine.
func Lookup(softwares []collector.SoftwareInfo) (*Result, error) {
	path := dbPath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("base CVE introuvable (%s) — lancez lockstate --update-cve", path)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("ouverture base CVE : %w", err)
	}
	defer db.Close()

	result := &Result{
		TotalChecked: len(softwares),
	}

	for _, sw := range softwares {
		vulns, err := searchByName(db, sw.Name, sw.Version)
		if err != nil {
			continue // On ne bloque pas le scan pour une erreur de lookup
		}
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}

	return result, nil
}

// searchByName cherche les CVE pour un logiciel donné.
// Stratégie de matching :
//  1. Match exact sur software_name + affected_version
//  2. Match partiel (LIKE) sur le nom pour couvrir les variantes
//  3. Comparaison de version : on retourne les CVE dont la version affectée
//     est >= à la version installée (logique simplifiée)
func searchByName(db *sql.DB, name, version string) ([]Vulnerability, error) {
	// Normaliser le nom pour le matching (minuscules, pas de suffixes de package)
	normalizedName := normalizeSoftwareName(name)

	query := `
		SELECT cve_id, software_name, affected_version, cvss_score, description, reference
		FROM cves
		WHERE LOWER(software_name) LIKE ?
		  AND (
		    affected_version = '*'
		    OR affected_version = ?
		    OR (affected_version_end != '' AND ? <= affected_version_end)
		  )
		ORDER BY cvss_score DESC
	`

	rows, err := db.Query(query, "%"+normalizedName+"%", version, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []Vulnerability
	for rows.Next() {
		var v Vulnerability
		var ref sql.NullString
		err := rows.Scan(&v.ID, &v.Software, &v.Version, &v.CVSS, &v.Description, &ref)
		if err != nil {
			continue
		}
		if ref.Valid {
			v.Reference = ref.String
		}
		v.Software = name // On garde le nom original, pas celui de la DB
		vulns = append(vulns, v)
	}

	return vulns, nil
}

// normalizeSoftwareName nettoie le nom pour améliorer le matching.
// Ex: "openssh-server" → "openssh", "libssl3" → "openssl"
func normalizeSoftwareName(name string) string {
	name = strings.ToLower(name)

	// Supprimer les suffixes de packaging courants
	suffixes := []string{"-server", "-client", "-common", "-dev", "-devel", "-libs", "-bin"}
	for _, s := range suffixes {
		name = strings.TrimSuffix(name, s)
	}

	// Aliases connus (package Linux → nom CPE standard)
	aliases := map[string]string{
		"libssl":      "openssl",
		"libssl3":     "openssl",
		"linux-image": "linux_kernel",
		"openjdk":     "jdk",
		"default-jdk": "jdk",
	}
	if alias, ok := aliases[name]; ok {
		return alias
	}

	return name
}
