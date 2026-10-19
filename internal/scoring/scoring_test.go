package scoring

import (
	"testing"
	"time"

	"lockstate/internal/collector"
)

func healthySystem() *collector.SystemInfo {
	return &collector.SystemInfo{
		Firewall:   collector.FirewallState{Enabled: true},
		Encryption: collector.EncryptionInfo{Enabled: true, DrivesCount: 1, DrivesTotal: 1},
	}
}

func item(t *testing.T, r *ScoreResult, category string) ScoreItem {
	t.Helper()
	for _, it := range r.Breakdown {
		if it.Category == category {
			return it
		}
	}
	t.Fatalf("catégorie %q absente de %+v", category, r.Breakdown)
	return ScoreItem{}
}

func countAlerts(r *ScoreResult, severity string) int {
	n := 0
	for _, a := range r.Alerts {
		if a.Severity == severity {
			n++
		}
	}
	return n
}

func TestCalculateHealthySystem(t *testing.T) {
	r := Calculate(Input{System: healthySystem()}, 0)
	if r.Global != 100 {
		t.Fatalf("score = %d, attendu 100 (alertes : %+v)", r.Global, r.Alerts)
	}
	if len(r.Alerts) != 0 {
		t.Errorf("aucune alerte attendue, obtenu %+v", r.Alerts)
	}
}

func TestCalculateFirewallAndEncryptionOff(t *testing.T) {
	sys := healthySystem()
	sys.Firewall.Enabled = false
	sys.Encryption = collector.EncryptionInfo{Enabled: false}

	r := Calculate(Input{System: sys}, 0)
	// Poids rapide : 25+20+15+10 = 70 ; il reste 20+15 = 35 de points → 50.
	if r.Global != 50 {
		t.Fatalf("score = %d, attendu 50", r.Global)
	}
	if got := countAlerts(r, "critical"); got != 2 {
		t.Errorf("alertes critiques = %d, attendu 2 (%+v)", got, r.Alerts)
	}
}

func TestCalculateHighRiskPorts(t *testing.T) {
	sys := healthySystem()
	sys.OpenPorts = []collector.PortInfo{{Port: 445}, {Port: 3389}, {Port: 22}}

	r := Calculate(Input{System: sys}, 0)
	// 2 ports à haut risque (-20 chacun) + 1 moyen (-10) → 50.
	if got := item(t, r, "Services exposés").Score; got != 50 {
		t.Errorf("score services = %d, attendu 50", got)
	}
}

// Régression : le collecteur Windows ne renseigne pas InstalledOn ; l'ancien code
// découpait p.InstalledOn[:10] et paniquait sur une chaîne vide.
func TestCalculatePatchesWithoutDateDoNotPanic(t *testing.T) {
	sys := healthySystem()
	sys.Patches = []collector.PatchInfo{{ID: "KB5000001"}, {ID: "KB5000002", InstalledOn: "n/a"}}

	r := Calculate(Input{System: sys}, 0)
	if got := item(t, r, "Mises à jour").Score; got != 100 {
		t.Errorf("score mises à jour = %d, attendu 100 quand aucune date n'est exploitable", got)
	}
}

func TestCalculateUsesNewestPatch(t *testing.T) {
	day := func(daysAgo int) string { return time.Now().AddDate(0, 0, -daysAgo).Format("2006-01-02") }

	recent := healthySystem()
	recent.Patches = []collector.PatchInfo{
		{ID: "KB-OLD", InstalledOn: day(400)},
		{ID: "KB-NEW", InstalledOn: day(5)},
	}
	if got := item(t, Calculate(Input{System: recent}, 0), "Mises à jour").Score; got != 100 {
		t.Errorf("un correctif récent doit donner 100, obtenu %d", got)
	}

	stale := healthySystem()
	stale.Patches = []collector.PatchInfo{{ID: "KB-OLD", InstalledOn: day(365)}}
	r := Calculate(Input{System: stale}, 0)
	if got := item(t, r, "Mises à jour").Score; got != 0 {
		t.Errorf("un correctif vieux d'un an doit donner 0, obtenu %d", got)
	}
	if countAlerts(r, "high") == 0 {
		t.Errorf("une alerte « dernière mise à jour » est attendue : %+v", r.Alerts)
	}
}

func TestNewestPatchDate(t *testing.T) {
	if _, ok := newestPatchDate(nil); ok {
		t.Error("aucune date attendue pour une liste vide")
	}
	got, ok := newestPatchDate([]collector.PatchInfo{
		{InstalledOn: ""},
		{InstalledOn: "pas une date"},
		{InstalledOn: "2024-03-01T10:00:00Z"},
		{InstalledOn: "2025-06-15"},
	})
	if !ok || got.Format("2006-01-02") != "2025-06-15" {
		t.Errorf("newestPatchDate = %v (%v), attendu 2025-06-15", got, ok)
	}
}
