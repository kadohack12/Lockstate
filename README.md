<div align="center">

# 🔐 LockState

**Audit de sécurité local, offline, autonome.**

Un binaire. Zéro dépendance. Aucune donnée ne quitte votre machine.

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS-blue?style=flat-square)]()
[![Release](https://img.shields.io/github/v/release/kadohack12/lockstate?style=flat-square&color=orange)]()

</div>

---

## Pourquoi LockState ?

Les outils d'audit de sécurité existants sont soit **trop lourds** (Nessus, OpenVAS), soit **trop dépendants** (scripts Python avec 50 packages), soit **envoient vos données dans le cloud**.

LockState est l'inverse :

| | Outils classiques | LockState |
|---|---|---|
| **Installation** | Agent + serveur + base de données | Un seul binaire (~5 Mo) |
| **Dépendances** | Python, Java, Node.js... | Aucune |
| **Données** | Cloud / SaaS | 100% local — rien ne sort |
| **Vitesse** | Minutes à heures | < 2 min (mode quick) |
| **Cible** | Infrastructure réseau | Poste de travail / serveur unique |

---

## Fonctionnalités

### 🔍 Collecte système
- **Windows** : API Win32 directes, registre, `netstat`, BitLocker, logiciels installés
- **Linux** : `/proc`, `/etc`, `iptables`/`ufw`, LUKS, `dpkg`/`rpm`

### 🗝️ Scanner de secrets
- 13 patterns regex précis (clés privées, tokens API, mots de passe en clair)
- Concurrence limitée avec timeout configurable
- Snippets tronqués — **jamais de secret affiché en clair dans le rapport**

### 🛡️ Détection de vulnérabilités
- Pare-feu désactivé
- Chiffrement disque absent ou partiel
- Ports à haut risque ouverts (SMB, RDP, Telnet, Redis...)
- Comptes administrateur actifs non légitimes
- Credentials en clair sur le filesystem

### 📦 Base CVE locale (SQLite)
- Lookup offline — pas de requête réseau pendant l'audit
- Mise à jour différenciée via l'API NVD v2.0 (`--update-cve`)
- Matching intelligent avec normalisation des noms logiciels
- Pilote SQLite pur Go — pas de CGO, pas de `.dll`

### 📊 Scoring pondéré
- Score global 0–100 avec 6 catégories pondérées
- Seuils d'alerte (critique, élevé, modéré, faible)
- Poids configurables par catégorie

### 📄 Rapport HTML autonome
- Template embarqué via `go:embed` — aucun fichier externe
- Score visuel avec jauge colorée
- Tableau détaillé par catégorie avec barres de progression
- Alertes triées par sévérité

---

## Installation

### Option 1 : Télécharger le binaire (recommandé)

1. Allez sur [Releases](https://github.com/kadohack12/lockstate/releases) et téléchargez le binaire correspondant à votre OS.

```bash
# Linux / macOS
chmod +x lockstate
./lockstate --mode quick
```

```powershell
# Windows
.\lockstate.exe --mode quick
```

### Option 2 : Compiler depuis les sources

```bash
git clone https://github.com/kadohack12/lockstate.git
cd lockstate
go mod tidy
go build -o lockstate ./cmd/lockstate/
```

### Option 3 : Cross-compilation

```bash
make all        # Compile pour Windows, Linux, macOS
make release    # + strip + UPX (binaire optimisé)
```

---

## Utilisation

### Modes d'audit

```bash
# Quick — < 2 min (collecte système + détection basique)
lockstate --mode quick

# Standard — < 10 min (+ scan credentials)
lockstate --mode standard

# Deep — > 10 min (+ scan étendu + lookup CVE)
lockstate --mode deep
```

### Options

| Flag | Description | Défaut |
|---|---|---|
| `--mode` | Mode d'audit : `quick`, `standard`, `deep` | `quick` |
| `--output` | Chemin du rapport de sortie | `lockstate_report.html` |
| `--skip` | Modules à ignorer (séparés par `,`) | _(aucun)_ |
| `--update-cve` | Mettre à jour la base CVE locale depuis NVD | `false` |
| `--config` | Fichier de configuration YAML | _(aucun)_ |
| `--quiet` | Mode silencieux (pas de logs) | `false` |

### Exemples concrets

```bash
# Audit rapide avec rapport JSON
lockstate --mode quick --output rapport.json

# Audit complet sans scanner les credentials
lockstate --mode deep --skip credentials

# Mettre à jour la base CVE puis lancer un audit deep
lockstate --update-cve
lockstate --mode deep --output audit_$(date +%Y%m%d).html
```

### Codes de sortie

| Code | Signification |
|---|---|
| `0` | Score ≥ 70 — Risque faible à modéré |
| `1` | Score 40–69 — Risque élevé |
| `2` | Score < 40 — Risque critique |

> Utile pour l'intégration dans des pipelines CI/CD ou des scripts d'automatisation.

---

## Cas d'usage

### 🏢 Audit pré-déploiement
Avant de mettre un serveur en production, lancez `lockstate --mode deep` pour vérifier qu'aucun port dangereux n'est ouvert, que le chiffrement est actif, et qu'aucun secret ne traîne dans les fichiers de configuration.

### 📋 Revue de conformité rapide
Un RSSI ou un auditeur peut exécuter LockState sur les postes de travail de l'entreprise pour obtenir un score de risque en moins de 2 minutes, sans installer quoi que ce soit ni envoyer de données.

### 🔬 Forensic léger
Lors d'un incident, utilisez LockState pour dresser un état des lieux rapide : ports ouverts, services actifs, comptes admin, secrets exposés. Le rapport HTML est autonome et peut être archivé.

### 🧪 Hardening validation
Après avoir appliqué des mesures de durcissement (CIS Benchmarks, ANSSI...), relancez LockState pour mesurer l'amélioration du score.

### 🤖 Intégration CI/CD
Grâce aux codes de sortie, LockState peut bloquer un pipeline si le score tombe en dessous d'un seuil.

```yaml
- name: Security Audit
  run: |
    ./lockstate --mode standard --quiet
    # Exit code 2 = critique → pipeline bloqué
```

---

## Architecture

```
lockstate/
├── cmd/lockstate/main.go           # Orchestrateur CLI (4 phases)
├── internal/
│   ├── collector/                  # Abstraction OS (Windows / Linux)
│   │   ├── collector.go            # Types + routeur
│   │   ├── windows.go              # Win32 API, registre, netstat
│   │   └── linux.go                # /proc, /etc, dpkg/rpm
│   ├── scanner/
│   │   └── filesystem.go           # Scanner credentials (13 regex)
│   ├── detector/
│   │   └── detector.go             # Règles de détection internes
│   ├── cve/
│   │   ├── cve.go                  # Lookup SQLite local
│   │   └── updater.go              # Fetch NVD API v2.0
│   ├── scoring/
│   │   └── scoring.go              # Scoring pondéré 0-100
│   └── report/
│       ├── html.go                 # Générateur via go:embed
│       └── templates/report.html   # Template embarqué
├── scripts/seed_cve.go             # Seed base CVE de test
├── configs/lockstate.yaml          # Configuration par défaut
├── go.mod                          # 2 dépendances (x/sys + sqlite)
└── Makefile                        # Build cross-platform
```

### Pipeline d'exécution

```
┌─────────────┐    ┌──────────┐    ┌──────────┐    ┌─────────┐    ┌─────────┐    ┌────────┐
│  Collector   │───▶│ Scanner  │───▶│ Detector │───▶│   CVE   │───▶│ Scoring │───▶│ Report │
│ (OS data)    │    │(secrets) │    │ (rules)  │    │(SQLite) │    │(0-100)  │    │ (HTML) │
└─────────────┘    └──────────┘    └──────────┘    └─────────┘    └─────────┘    └────────┘
```

---

## Dépendances

| Package | Usage | Justification |
|---|---|---|
| [`golang.org/x/sys`](https://pkg.go.dev/golang.org/x/sys) | API Windows (registre, syscalls) | Officiel Go, nécessaire pour les appels Win32 |
| [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite) | Base CVE locale | Pur Go, pas de CGO, binaire 100% portable |

**Zéro framework. Zéro dépendance runtime. Binaire statique de ~5 Mo.**

---

## Contribuer

Les contributions sont les bienvenues ! Consultez [CONTRIBUTING.md](CONTRIBUTING.md) pour les guidelines.

### Ajouter une règle de détection

Ajoutez votre règle dans `internal/detector/detector.go` :

```go
// Règle N : Votre nouvelle vérification
if conditionDétectée {
    result.Findings = append(result.Findings, Finding{
        ID:          "CUSTOM-001",
        Title:       "Description courte",
        Description: "Description détaillée de la vulnérabilité.",
        Severity:    "high",     // critical, high, medium, low
        Category:    "Custom",
        Status:      "Failed",
        Remediation: "Comment corriger le problème.",
    })
}
```

### Ajouter un pattern de credential

Ajoutez votre regex dans `internal/scanner/filesystem.go` :

```go
{"mon_pattern", regexp.MustCompile(`(?i)ma_regex_ici`), "high"},
```

---

## Roadmap

- [x] Collecteur Windows (registre, API Win32)
- [x] Collecteur Linux (/proc, /etc)
- [x] Scanner de credentials (13 patterns)
- [x] Détecteur de vulnérabilités (6 règles)
- [x] Base CVE locale (SQLite + NVD API v2.0)
- [x] Scoring pondéré (6 catégories)
- [x] Rapport HTML embarqué (go:embed)
- [ ] Collecteur macOS (Darwin)
- [ ] Export JSON / PDF
- [ ] Mode comparaison (diff entre deux audits)
- [ ] Règles CIS Benchmark
- [ ] Support des API keys NVD (rate-limit x10)
- [ ] Interface TUI (terminal UI)

---

## Licence

Ce projet est distribué sous licence [MIT](LICENSE). Vous êtes libre de l'utiliser, le modifier et le distribuer.

---

<div align="center">

**Construit avec 🔒 par [KADOHACK12](https://github.com/KADOHACK12)**

*LockState — Parce que la sécurité commence sur votre propre machine.*

</div>
