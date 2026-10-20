# Changelog

Toutes les modifications remarquables de ce projet sont documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) et ce projet adhère au [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-20

### Added
- Audit local hors ligne : collecte système (Windows, Linux), détection de risques (6 règles), scoring pondéré 0-100
- Scanner de secrets (13 patterns regex), extraits masqués dans les rapports
- Base CVE locale (SQLite pur Go) et mise à jour via l'API NVD v2.0 (`--update-cve`)
- Rapports HTML autonome et JSON (selon l'extension de `--output`)
- Modes `quick`, `standard` et `deep` ; codes de sortie 0/1/2 selon le score, 3 en cas d'erreur
- Tests unitaires (scanner, scoring, CLI) et CI : gofmt, `go vet` cross-OS, `go test -race`, release avec `SHA256SUMS`

### Fixed
- `cmd/lockstate/` n'était pas versionné (pattern `lockstate` non ancré dans `.gitignore`) : le dépôt ne compilait pas
- Les collecteurs Windows et Linux ne compilaient pas
- Panique du scoring sur une date de correctif vide
- La regex `private_key` ne détectait pas `RSA`/`EC`/`OPENSSH PRIVATE KEY`

### Known limitations
- Pas de collecteur macOS ; `--config` est accepté mais pas encore appliqué ; pondérations du score fixes
- Zéro dépendance à l'exécution, mais deux dépendances de build : `golang.org/x/sys` et `modernc.org/sqlite`
