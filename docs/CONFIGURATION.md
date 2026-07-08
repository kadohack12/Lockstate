# LockState Configuration

Configuration et données par défaut pour LockState.

## Configuration

Voir [configs/lockstate.yaml](configs/lockstate.yaml) pour les paramètres disponibles :

- **Mode** : quick, standard, deep
- **Timeouts** : Durée maximale des analyses
- **Patterns** : Patterns regex pour la détection de secrets
- **Scoring** : Poids des différentes catégories

## Base de données CVE

Placez votre base SQLite dans un dossier `data/` :

```bash
mkdir -p data
# La base sera générée ou mise à jour automatiquement
```

Le fichier `.gitignore` exclut les fichiers `.db` et `.sqlite` pour ne pas versionner les données.
