# Changelog

Toutes les modifications remarquables de ce projet sont documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) et ce projet adhère au [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- (Ajoutez les nouvelles fonctionnalités en développement)

### Changed
- (Changements en cours)

### Fixed
- (Corrections en cours)

### Security
- (Corrections de sécurité en cours)

## [0.1.0] - 2024-XX-XX

### Added
- Scanner de vulnérabilités local
- Collecte d'informations système (Windows, Linux, macOS)
- Détection de secrets (13 patterns regex)
- Base de données CVE locale (SQLite)
- Scoring de sécurité pondéré (0-100)
- Rapport HTML autonome
- Mode quick (< 2 min), standard (< 10 min), deep (> 30 min)
- Mise à jour CVE via API NVD v2.0
- Zéro dépendance externe
- Binaire multiplateforme

### Changed
- (Première version - pas de changements)

### Security
- Tous les secrets sont tronqués dans les rapports
- Pas de données envoyées au cloud
- Données stockées localement uniquement
