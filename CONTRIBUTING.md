# Contribuer à LockState

Merci de votre intérêt pour contribuer à LockState ! 🙏

## Comment contribuer

### Signaler un bug

1. Vérifiez que le bug n'existe pas déjà sur [Issues](https://github.com/kadohack12/lockstate/issues)
2. Créez une nouvelle issue avec :
   - Une description claire du problème
   - Les étapes pour reproduire
   - Votre OS et version de Go (`go version`)
   - La sortie complète de l'erreur

### Proposer une fonctionnalité

1. Ouvrez une discussion dans [Discussions](https://github.com/kadohack12/lockstate/discussions)
2. Décrivez le cas d'usage et l'implémentation proposée
3. Attendez les retours avant de commencer le développement

### Envoyer une Pull Request

#### Setup local

```bash
git clone https://github.com/KADOHACK12/lockstate.git
cd lockstate
go mod tidy
go build -o lockstate ./cmd/lockstate/
```

#### Développer

1. Créez une branche depuis `develop` :
   ```bash
   git checkout -b feature/ma-fonctionnalite
   ```

2. Commitez avec des messages clairs :
   ```bash
   git commit -m "feat: ajouter nouvelle détection"
   ```

3. Poussez et ouvrez une PR vers `develop`

#### Standards de code

- **Format** : Utilisez `gofmt` avant de commiter
- **Tests** : Ajoutez des tests pour les nouvelles fonctionnalités
- **Documentation** : Commentez les fonctions publiques
- **Pas de dépendances externes** : Respectez la philosophie "zéro dépendance"

## Questions ?

Ouvrez une [Discussion](https://github.com/KADOHACK12/lockstate/discussions) ou contactez-nous par issue.

Merci ! 🚀
