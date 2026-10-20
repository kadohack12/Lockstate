# Installation

Windows et Linux sont supportés. macOS compile, mais le binaire s'arrête avec « OS non supporté » : il n'y a pas encore de collecteur Darwin (voir la [roadmap](README.md#roadmap)).

## Option 1 : binaire (recommandé)

1. Téléchargez le binaire de votre OS depuis les [Releases](https://github.com/kadohack12/lockstate/releases), avec le fichier `SHA256SUMS`.
2. Vérifiez puis lancez :

```bash
# Linux
sha256sum -c --ignore-missing SHA256SUMS
chmod +x lockstate-*-linux-amd64
./lockstate-*-linux-amd64 --mode quick
```

```powershell
# Windows
.\lockstate-0.1.0-windows-amd64.exe --mode quick
```

## Option 2 : depuis les sources

Go 1.22+ requis.

```bash
git clone https://github.com/kadohack12/lockstate.git
cd lockstate
go build -o lockstate ./cmd/lockstate/
./lockstate --mode quick
```

`go install github.com/kadohack12/lockstate/cmd/lockstate@latest` ne fonctionne pas : le module s'appelle `lockstate` dans `go.mod`, pas `github.com/kadohack12/lockstate`.

## Utilisation

```bash
lockstate --mode quick                          # rapport HTML dans le répertoire courant
lockstate --mode standard --output rapport.json # rapport JSON (selon l'extension)
lockstate --mode deep --skip cve                # deep sans lookup CVE
lockstate --update-cve                          # met à jour la base CVE locale puis quitte
```

| Mode | Contenu |
|---|---|
| `quick` | Collecte système + détection |
| `standard` | + scan de secrets |
| `deep` | + scan étendu et lookup CVE (base requise : `--update-cve`) |

`--skip` accepte `credentials` (alias `secrets`) et `cve`. Les codes de sortie (0, 1, 2, 3) sont décrits dans le [README](README.md#codes-de-sortie).

## Dépannage

- **« base CVE introuvable »** (mode deep) : lancez `lockstate --update-cve`. La mise à jour respecte la limite de l'API NVD (~6,5 s par mot-clé), comptez quelques minutes.
- **Pas de scan de secrets** : le mode `quick` ne le lance pas, utilisez `--mode standard` ou `deep`.
- **Voir les logs** : `lockstate --mode quick 2>&1 | tee debug.log`
- **Erreur de compilation** : vérifiez `go version` (1.22 minimum).

Un problème de sécurité ? Voir [SECURITY.md](SECURITY.md).
