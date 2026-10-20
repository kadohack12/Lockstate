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
- `collector.go` : Types et `Collect()`
- `platform_*.go` : sélection du collecteur par build tag (linux, windows, autres)
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
1. Parsing des flags (`--update-cve` met à jour la base puis quitte)
2. Collecte système
3. Scan de secrets (standard et deep)
4. Détection de risques
5. Lookup CVE (deep)
6. Calcul du score
7. Génération du rapport (HTML ou JSON selon l'extension)
```

## Dépendances minimales

- `golang.org/x/sys` : Appels système cross-plateforme
- `modernc.org/sqlite` : Driver SQLite pur Go (pas de CGO)

## Performance

- **Mode quick** : collecte système + détection, pas de scan de secrets ni de CVE
- **Mode standard** : + scan de secrets
- **Mode deep** : + scan étendu (profondeur 10, timeout 300 s) + lookup CVE
