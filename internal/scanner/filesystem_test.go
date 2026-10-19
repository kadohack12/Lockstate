package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanFilePatterns(t *testing.T) {
	githubToken := "ghp_" + strings.Repeat("a", 36)

	tests := []struct {
		name    string
		line    string
		pattern string
		risk    string
		secret  string // valeur qui ne doit jamais apparaître dans l'extrait
	}{
		{"mot de passe ini", "password = hunter2hunter2", "password_in_ini", "high", "hunter2"},
		{"clé privée RSA", "-----BEGIN RSA PRIVATE KEY-----", "private_key", "critical", "RSA"},
		{"clé privée OpenSSH", "-----BEGIN OPENSSH PRIVATE KEY-----", "private_key", "critical", "OPENSSH"},
		{"clé privée EC", "-----BEGIN EC PRIVATE KEY-----", "private_key", "critical", "EC PRIVATE"},
		{"clé privée PKCS#8", "-----BEGIN PRIVATE KEY-----", "private_key", "critical", "PKCS"},
		{"clé AWS", "AKIAIOSFODNN7EXAMPLE", "aws_access_key", "critical", "IOSFODNN7EXAMPLE"},
		{"token GitHub", "export X=" + githubToken, "github_token", "critical", githubToken},
		{"mot de passe JSON", `"password": "s3cretvalue"`, "json_password", "high", "s3cretvalue"},
		{"mot de passe XML", "<password>topsecret</password>", "xml_password", "high", "topsecret"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.txt")
			if err := os.WriteFile(path, []byte("rien à signaler\n"+tc.line+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			findings := scanFile(path, defaultConfig)
			if len(findings) != 1 {
				t.Fatalf("attendu 1 résultat, obtenu %d : %+v", len(findings), findings)
			}
			f := findings[0]
			if f.PatternName != tc.pattern || f.Risk != tc.risk {
				t.Errorf("pattern/risque = %s/%s, attendu %s/%s", f.PatternName, f.Risk, tc.pattern, tc.risk)
			}
			if f.LineNumber != 2 {
				t.Errorf("ligne = %d, attendu 2", f.LineNumber)
			}
			if strings.Contains(f.Snippet, tc.secret) {
				t.Errorf("l'extrait contient le secret : %q", f.Snippet)
			}
		})
	}
}

func TestScanFileNoMatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(path, []byte("hello world\nrien d'intéressant\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if findings := scanFile(path, defaultConfig); len(findings) != 0 {
		t.Fatalf("aucun résultat attendu, obtenu %+v", findings)
	}
}

func TestMaskSnippet(t *testing.T) {
	tests := []struct{ in, want string }{
		{"password = hunter2hunter2", "password = [masqué]"},
		{`"token": "abcdefghijklmnopqrstuvwxyz"`, `"token": [masqué]`},
		{"AKIAIOSFODNN7EXAMPLE", "AKIA… [masqué]"},
		{"  DB_PASSWORD=supersecret  ", "DB_PASSWORD= [masqué]"},
		{"", "… [masqué]"},
	}
	for _, tc := range tests {
		if got := maskSnippet(tc.in); got != tc.want {
			t.Errorf("maskSnippet(%q) = %q, attendu %q", tc.in, got, tc.want)
		}
	}

	// Une longue chaîne base64 avec padding ne doit jamais fuiter, même si « = » apparaît tard.
	b64 := strings.Repeat("A", 44) + "=="
	if got := maskSnippet(b64); strings.Contains(got, strings.Repeat("A", 10)) {
		t.Errorf("fuite de base64 dans l'extrait : %q", got)
	}
}
