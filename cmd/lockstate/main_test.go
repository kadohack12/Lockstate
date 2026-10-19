package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseMode(t *testing.T) {
	for in, want := range map[string]int{"quick": 0, "standard": 1, "deep": 2, " DEEP ": 2} {
		got, err := parseMode(in)
		if err != nil || got != want {
			t.Errorf("parseMode(%q) = %d, %v ; attendu %d", in, got, err, want)
		}
	}
	if _, err := parseMode("turbo"); err == nil {
		t.Error("un mode inconnu doit être refusé")
	}
}

func TestParseSkip(t *testing.T) {
	skipped, unknown := parseSkip("secrets, CVE ,firewall,")
	if !skipped["credentials"] || !skipped["cve"] {
		t.Errorf("modules ignorés = %v, attendu credentials et cve", skipped)
	}
	if len(unknown) != 1 || unknown[0] != "firewall" {
		t.Errorf("modules inconnus = %v, attendu [firewall]", unknown)
	}
}

func TestExitCodeForScore(t *testing.T) {
	tests := map[int]int{100: exitOK, 70: exitOK, 69: exitHigh, 40: exitHigh, 39: exitCritical, 0: exitCritical}
	for score, want := range tests {
		if got := exitCodeForScore(score); got != want {
			t.Errorf("exitCodeForScore(%d) = %d, attendu %d", score, got, want)
		}
	}
}

func TestRunVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"--version"}, &out, &errOut); code != exitOK {
		t.Fatalf("code = %d, attendu %d", code, exitOK)
	}
	if !strings.HasPrefix(out.String(), "lockstate ") {
		t.Errorf("sortie inattendue : %q", out.String())
	}
}

func TestRunRejectsBadArguments(t *testing.T) {
	for _, args := range [][]string{
		{"--mode", "turbo"},
		{"--nope"},
		{"--config", filepath.Join(t.TempDir(), "absent.yaml")},
	} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != exitError {
			t.Errorf("run(%v) = %d, attendu %d", args, code, exitError)
		}
	}
}

// Exécution réelle de bout en bout : collecte système, scoring et rapport JSON.
func TestRunQuickEndToEnd(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skipf("pas de collecteur pour %s", runtime.GOOS)
	}

	report := filepath.Join(t.TempDir(), "rapport.json")
	var out, errOut bytes.Buffer
	code := run([]string{"--mode", "quick", "--quiet", "--output", report}, &out, &errOut)
	if code != exitOK && code != exitHigh && code != exitCritical {
		t.Fatalf("code = %d, stderr : %s", code, errOut.String())
	}

	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatalf("rapport non généré : %v", err)
	}
	var parsed struct {
		Score     int               `json:"score"`
		Breakdown []json.RawMessage `json:"breakdown"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("rapport JSON invalide : %v", err)
	}
	if parsed.Score < 0 || parsed.Score > 100 || len(parsed.Breakdown) == 0 {
		t.Errorf("rapport incohérent : score=%d, catégories=%d", parsed.Score, len(parsed.Breakdown))
	}
	if want := exitCodeForScore(parsed.Score); code != want {
		t.Errorf("code de sortie %d incohérent avec le score %d (attendu %d)", code, parsed.Score, want)
	}
}
