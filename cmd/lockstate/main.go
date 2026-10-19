// LockState — audit de sécurité local, offline et autonome.
//
// Pipeline : collecte système → scan de secrets → détection → lookup CVE →
// scoring → rapport. Le code de sortie reflète le score global :
//
//	0 : score >= 70 (risque faible à modéré)
//	1 : score 40–69 (risque élevé)
//	2 : score < 40  (risque critique)
//	3 : erreur d'exécution (flags invalides, collecte impossible, rapport illisible)
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"

	"lockstate/internal/collector"
	"lockstate/internal/cve"
	"lockstate/internal/detector"
	"lockstate/internal/report"
	"lockstate/internal/scanner"
	"lockstate/internal/scoring"
	"lockstate/internal/utils"
)

// Version est injectée au build : -ldflags "-X main.Version=0.1.0".
var Version = "dev"

const (
	exitOK       = 0
	exitHigh     = 1
	exitCritical = 2
	exitError    = 3
)

// Niveaux d'audit, alignés sur le paramètre `mode` de detector, scanner et scoring.
const (
	modeQuick    = 0
	modeStandard = 1
	modeDeep     = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run exécute l'audit complet et retourne le code de sortie du processus.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lockstate", flag.ContinueOnError)
	fs.SetOutput(stderr)

	modeFlag := fs.String("mode", "quick", "mode d'audit : quick, standard, deep")
	output := fs.String("output", "lockstate_report.html", "chemin du rapport (.html ou .json)")
	skip := fs.String("skip", "", "modules à ignorer, séparés par des virgules (credentials, cve)")
	updateCVE := fs.Bool("update-cve", false, "mettre à jour la base CVE locale depuis NVD puis quitter")
	configPath := fs.String("config", "", "fichier de configuration YAML (non appliqué pour l'instant)")
	quiet := fs.Bool("quiet", false, "mode silencieux (aucun log)")
	showVersion := fs.Bool("version", false, "afficher la version")

	if err := fs.Parse(args); err != nil {
		return exitError
	}

	if *showVersion {
		fmt.Fprintf(stdout, "lockstate %s\n", Version)
		return exitOK
	}

	logf := func(format string, a ...any) {
		if !*quiet {
			fmt.Fprintf(stderr, format+"\n", a...)
		}
	}
	if *quiet {
		log.SetOutput(io.Discard)
	} else {
		log.SetOutput(stderr)
	}

	// ── Mise à jour de la base CVE ──
	if *updateCVE {
		logf("Mise à jour de la base CVE (API NVD v2.0, rate-limit ~6,5 s par mot-clé)…")
		if err := cve.UpdateDatabase(); err != nil {
			fmt.Fprintf(stderr, "erreur : mise à jour CVE : %v\n", err)
			return exitError
		}
		return exitOK
	}

	mode, err := parseMode(*modeFlag)
	if err != nil {
		fmt.Fprintf(stderr, "erreur : %v\n", err)
		return exitError
	}

	skipped, unknown := parseSkip(*skip)
	for _, name := range unknown {
		logf("avertissement : module inconnu ignoré dans --skip : %q (valeurs : credentials, cve)", name)
	}

	if *configPath != "" {
		if !utils.FileExists(*configPath) {
			fmt.Fprintf(stderr, "erreur : fichier de configuration introuvable : %s\n", *configPath)
			return exitError
		}
		logf("avertissement : --config est accepté mais le fichier n'est pas encore appliqué")
	}

	// ── Phase 1 : collecte système ──
	logf("[1/4] Collecte système (%s)…", runtime.GOOS)
	sysInfo, err := collector.Collect(runtime.GOOS)
	if err != nil {
		fmt.Fprintf(stderr, "erreur : %v\n", err)
		return exitError
	}

	// ── Phase 2 : scan de secrets (standard et deep) ──
	var scanResult *scanner.Result
	if mode >= modeStandard && !skipped["credentials"] {
		logf("[2/4] Scan de secrets…")
		scanResult, err = scanner.ScanCredentials(sysInfo, scanner.Mode(mode))
		if err != nil {
			logf("avertissement : scan de secrets impossible : %v", err)
			scanResult = nil
		}
	} else {
		logf("[2/4] Scan de secrets ignoré")
	}

	// ── Phase 3 : détection + lookup CVE (deep) ──
	logf("[3/4] Détection des risques…")
	detectResult := detector.Analyze(sysInfo, scanResult, mode)

	var cveResult *cve.Result
	if mode >= modeDeep && !skipped["cve"] {
		cveResult, err = cve.Lookup(sysInfo.Software)
		if err != nil {
			logf("avertissement : %v", err)
			cveResult = nil
		}
	}

	// ── Phase 4 : scoring + rapport ──
	logf("[4/4] Scoring et génération du rapport…")
	score := scoring.Calculate(scoring.Input{
		System: sysInfo,
		Scan:   scanResult,
		Detect: detectResult,
		CVE:    cveResult,
	}, scoring.Mode(mode))

	if err := report.Generate(sysInfo, score, *output); err != nil {
		fmt.Fprintf(stderr, "erreur : génération du rapport : %v\n", err)
		return exitError
	}

	logf("Score global : %d/100 — rapport : %s", score.Global, *output)
	return exitCodeForScore(score.Global)
}

// parseMode convertit le nom du mode en niveau d'audit.
func parseMode(s string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "quick":
		return modeQuick, nil
	case "standard":
		return modeStandard, nil
	case "deep":
		return modeDeep, nil
	default:
		return 0, fmt.Errorf("mode invalide %q (valeurs : quick, standard, deep)", s)
	}
}

// parseSkip lit la liste --skip. "secrets" est accepté comme alias de "credentials".
// Retourne l'ensemble des modules ignorés et la liste des noms non reconnus.
func parseSkip(s string) (skipped map[string]bool, unknown []string) {
	skipped = map[string]bool{}
	for _, raw := range strings.Split(s, ",") {
		name := strings.ToLower(strings.TrimSpace(raw))
		switch name {
		case "":
		case "credentials", "secrets":
			skipped["credentials"] = true
		case "cve":
			skipped["cve"] = true
		default:
			unknown = append(unknown, name)
		}
	}
	return skipped, unknown
}

// exitCodeForScore traduit le score global en code de sortie (utilisable en CI/CD).
func exitCodeForScore(score int) int {
	switch {
	case score >= 70:
		return exitOK
	case score >= 40:
		return exitHigh
	default:
		return exitCritical
	}
}
