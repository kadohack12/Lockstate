// Seed script — Crée une base CVE de test avec des données réalistes.
// Usage : go run scripts/seed_cve.go
//
// Ce script crée le fichier data/cve.db avec quelques CVE connues
// pour valider le fonctionnement du module de lookup.
package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "modernc.org/sqlite"
)

const schema = `
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

type testCVE struct {
	ID, Software, Version, VersionEnd, Desc, Ref, Published string
	CVSS                                                     float64
}

func main() {
	os.MkdirAll("data", 0755)

	db, err := sql.Open("sqlite", "data/cve.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if _, err := db.Exec(schema); err != nil {
		log.Fatal(err)
	}

	// ── CVE de test réalistes ──
	cves := []testCVE{
		// OpenSSH
		{
			ID: "CVE-2024-6387", Software: "openssh", Version: "*", VersionEnd: "9.8",
			CVSS: 8.1, Desc: "regreSSHion: Race condition in OpenSSH server (sshd) signal handler allows unauthenticated remote code execution.",
			Ref: "https://nvd.nist.gov/vuln/detail/CVE-2024-6387", Published: "2024-07-01",
		},
		{
			ID: "CVE-2023-51385", Software: "openssh", Version: "*", VersionEnd: "9.6",
			CVSS: 6.5, Desc: "OS command injection via ssh agent forwarding with ProxyCommand.",
			Ref: "https://nvd.nist.gov/vuln/detail/CVE-2023-51385", Published: "2023-12-18",
		},
		// OpenSSL
		{
			ID: "CVE-2024-5535", Software: "openssl", Version: "*", VersionEnd: "3.3.2",
			CVSS: 9.1, Desc: "SSL_select_next_proto buffer overread leads to crash or information disclosure.",
			Ref: "https://nvd.nist.gov/vuln/detail/CVE-2024-5535", Published: "2024-06-27",
		},
		{
			ID: "CVE-2024-0727", Software: "openssl", Version: "*", VersionEnd: "3.2.1",
			CVSS: 5.5, Desc: "NULL dereference when processing PKCS12 with no certificate bag.",
			Ref: "https://nvd.nist.gov/vuln/detail/CVE-2024-0727", Published: "2024-01-26",
		},
		// Apache
		{
			ID: "CVE-2024-38476", Software: "apache", Version: "*", VersionEnd: "2.4.62",
			CVSS: 9.8, Desc: "Apache HTTP Server: Exploitable/Denial of Service via WebSocket over HTTP/2.",
			Ref: "https://nvd.nist.gov/vuln/detail/CVE-2024-38476", Published: "2024-07-01",
		},
		// Nginx
		{
			ID: "CVE-2024-7347", Software: "nginx", Version: "1.5.6", VersionEnd: "1.27.1",
			CVSS: 4.7, Desc: "Buffer over-read in ngx_http_mp4_module processing of mp4 files.",
			Ref: "https://nvd.nist.gov/vuln/detail/CVE-2024-7347", Published: "2024-08-14",
		},
		// Redis
		{
			ID: "CVE-2024-31449", Software: "redis", Version: "*", VersionEnd: "7.2.6",
			CVSS: 8.8, Desc: "Lua library commands may lead to stack overflow and RCE in Redis.",
			Ref: "https://nvd.nist.gov/vuln/detail/CVE-2024-31449", Published: "2024-10-07",
		},
		// sudo
		{
			ID: "CVE-2023-22809", Software: "sudo", Version: "1.8.0", VersionEnd: "1.9.12p1",
			CVSS: 7.8, Desc: "sudoedit in sudo allows arbitrary file write via user-provided environment variables.",
			Ref: "https://nvd.nist.gov/vuln/detail/CVE-2023-22809", Published: "2023-01-18",
		},
		// Chromium / Google Chrome
		{
			ID: "CVE-2024-7971", Software: "chromium", Version: "*", VersionEnd: "128.0.6613.84",
			CVSS: 8.8, Desc: "Type confusion in V8 JavaScript engine allows remote code execution via crafted HTML page.",
			Ref: "https://nvd.nist.gov/vuln/detail/CVE-2024-7971", Published: "2024-08-21",
		},
		// PuTTY
		{
			ID: "CVE-2024-31497", Software: "putty", Version: "0.68", VersionEnd: "0.80",
			CVSS: 5.9, Desc: "Biased ECDSA nonce generation in PuTTY allows recovery of NIST P-521 private keys.",
			Ref: "https://nvd.nist.gov/vuln/detail/CVE-2024-31497", Published: "2024-04-15",
		},
		// 7-Zip
		{
			ID: "CVE-2024-11477", Software: "7-zip", Version: "*", VersionEnd: "24.07",
			CVSS: 7.8, Desc: "Zstandard decompression integer underflow in 7-Zip allows remote code execution.",
			Ref: "https://nvd.nist.gov/vuln/detail/CVE-2024-11477", Published: "2024-11-22",
		},
		// Docker
		{
			ID: "CVE-2024-41110", Software: "docker", Version: "19.03.0", VersionEnd: "27.1.1",
			CVSS: 10.0, Desc: "AuthZ plugin bypass in Docker Engine allows unauthorized actions including privilege escalation.",
			Ref: "https://nvd.nist.gov/vuln/detail/CVE-2024-41110", Published: "2024-07-24",
		},
	}

	stmt, err := db.Prepare(`
		INSERT OR REPLACE INTO cves 
		(cve_id, software_name, affected_version, affected_version_end, cvss_score, description, reference, published_date, last_modified)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()

	for _, c := range cves {
		_, err := stmt.Exec(c.ID, c.Software, c.Version, c.VersionEnd, c.CVSS, c.Desc, c.Ref, c.Published, c.Published)
		if err != nil {
			log.Printf("Erreur insertion %s : %v", c.ID, err)
			continue
		}
		fmt.Printf("  ✓ %s → %s (CVSS %.1f)\n", c.ID, c.Software, c.CVSS)
	}

	// Metadata
	db.Exec("INSERT OR REPLACE INTO metadata (key, value) VALUES ('last_modified', '2024-12-01T00:00:00Z')")
	db.Exec("INSERT OR REPLACE INTO metadata (key, value) VALUES ('source', 'seed_script')")

	fmt.Printf("\n✓ Base CVE de test créée : data/cve.db (%d entrées)\n", len(cves))
}
