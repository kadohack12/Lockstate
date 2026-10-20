# Guide d'installation pour développeurs

## Prérequis

- **Go** 1.22 ou supérieur
- **Make** (optionnel, mais recommandé)
- **Git**

## Installation locale

### 1. Cloner le repository

```bash
git clone https://github.com/kadohack12/lockstate.git
cd lockstate
```

### 2. Télécharger les dépendances

```bash
go mod download
```

### 3. Compiler pour votre OS

```bash
# Linux / macOS
go build -o lockstate ./cmd/lockstate/

# Windows (PowerShell)
go build -o lockstate.exe ./cmd/lockstate/
```

Ou utiliser `make` :

```bash
make all          # Compile pour Windows et Linux
make windows      # Compilation Windows uniquement
make linux        # Compilation Linux uniquement
make darwin       # Compile pour macOS, mais le binaire refuse de s'exécuter (pas de collecteur Darwin)
make test         # go vet + go test
make clean        # Nettoie les fichiers compilés
```

## Lancer en mode développement

```bash
go run ./cmd/lockstate/ --mode quick
```

## Tests

```bash
go test ./...
```

## Cross-compilation

```bash
# Pour Linux depuis Windows
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build -o lockstate-linux ./cmd/lockstate/

# Pour Windows depuis Linux
GOOS=windows GOARCH=amd64 go build -o lockstate.exe ./cmd/lockstate/
```

## Structure du code

```
cmd/lockstate/     → Entrée principale (main.go)
internal/          → Code interne (non-exportable)
  ├── collector/   → Collecte système
  ├── cve/         → Gestion CVE
  ├── detector/    → Détection des risques
  ├── report/      → Génération des rapports
  ├── scanner/     → Scanner de secrets
  ├── scoring/     → Calcul des scores
  └── utils/       → Utilitaires
configs/           → Fichiers de configuration
scripts/           → Scripts utilitaires
```

## Debug

### Activez le verbose mode

```bash
go run ./cmd/lockstate/ --mode quick
```

### Capturer les logs

```bash
go run ./cmd/lockstate/ --mode quick 2>&1 | tee debug.log
```

### Avec IDE VS Code

Créez `.vscode/launch.json` :

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Launch",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}/cmd/lockstate",
      "args": ["--mode", "quick"]
    }
  ]
}
```

Puis appuyez sur F5.

## Besoin d'aide ?

- 📖 [Documentation](docs/)
- 💬 [Discussions GitHub](https://github.com/kadohack12/lockstate/discussions)
- 🐛 [Signaler un bug](https://github.com/kadohack12/lockstate/issues)
