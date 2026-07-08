# Architecture de LockState

## Vue d'ensemble

```
LockState
├── Collecteur (collector)     → Informations système
├── Scanner (scanner)          → Recherche de secrets
├── Détecteur (detector)       → Identifie les risques
├── CVE (cve)                  → Lookup offline
├── Scoring (scoring)          → Calcul des risques
└── Rapport (report)           → Génération HTML
```

## Modules

### `collector` - Collecte système
- `collector.go` : Interface principale
- `windows.go` : Collecte spécifique Windows (WMI, API Win32)
- `linux.go` : Collecte spécifique Linux (/proc, iptables, etc.)

### `scanner` - Scanner de secrets
- `filesystem.go` : Parcours du filesystem et regex matching

### `detector` - Détection de risques
- `detector.go` : Logique de détection (pare-feu, chiffrement, ports, etc.)

### `cve` - Gestion des CVE
- `cve.go` : Requêtes SQLite
- `updater.go` : Synchronisation API NVD v2.0

### `scoring` - Calcul du score de sécurité
- `scoring.go` : Algorithme pondéré par catégorie

### `report` - Génération de rapports
- `report.go` : Logique de rapport
- `html.go` : Rendu HTML
- `templates/report.html` : Template embarqué (`go:embed`)

## Flux d'exécution

```
1. Parsing des flags
2. (Optionnel) Mise à jour CVE
3. Collecte système
4. Scan de secrets
5. Détection de risques
6. Lookup CVE
7. Calcul du score
8. Génération rapport
9. Sauvegarde HTML
```

## Dépendances minimales

- `golang.org/x/sys` : Appels système cross-plateforme
- `modernc.org/sqlite` : Driver SQLite pur Go (pas de CGO)

## Performance

- **Mode quick** : Scan rapide, pas d'accès CVE
- **Mode standard** : Scan complet + lookup CVE basique
- **Mode deep** : Scan exhaustif + deep CVE matching
