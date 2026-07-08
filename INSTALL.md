# Installation Guide / Guide d'installation

## 🚀 Installation utilisateur final

### Prérequis
- ✅ Windows / Linux / macOS
- ✅ Aucune dépendance externe requise

### Option 1 : Télécharger le binaire (Recommandé)

1. Allez sur [Releases](https://github.com/kadohack12/lockstate/releases)
2. Téléchargez le binaire pour votre OS :
   - `lockstate-X.X.X-windows-amd64.exe` (Windows)
   - `lockstate-X.X.X-linux-amd64` (Linux)
   - `lockstate-X.X.X-darwin-amd64` (macOS)

3. Rendez-le exécutable et lancez-le :

   **Linux / macOS** :
   ```bash
   chmod +x lockstate-*
   ./lockstate-* --mode quick
   ```

   **Windows** :
   ```powershell
   .\lockstate-*.exe --mode quick
   ```

### Option 2 : Installer avec Go

Si vous avez Go 1.22+ installé :

```bash
go install github.com/kadohack12/lockstate/cmd/lockstate@latest
lockstate --mode quick
```

### Option 3 : Compiler depuis les sources

```bash
git clone https://github.com/kadohack12/lockstate.git
cd lockstate
go build -o lockstate ./cmd/lockstate/
./lockstate --mode quick
```

---

## 📋 Premiers pas

### Audit rapide

```bash
lockstate --mode quick
```

Sortie : rapport HTML dans le répertoire courant

### Modes d'audit

- **quick** (< 2 min) : Vérifications essentielles uniquement
- **standard** (< 10 min) : Audit complet sans lookup CVE approfondi
- **deep** (> 30 min) : Scan exhaustif avec matching CVE détaillé

```bash
lockstate --mode standard --output ./rapport-complet.html
```

### Options avancées

```bash
lockstate \
  --mode deep \
  --output ./rapport.html \
  --config ./custom.yaml \
  --skip "secrets,firewall"
```

### Mise à jour de la base CVE

```bash
lockstate --update-cve
```

---

## ❓ Dépannage

### Permission denied (Linux/macOS)

```bash
chmod +x lockstate-*
```

### "Cannot find module" (compilation)

```bash
go mod tidy
go build ./cmd/lockstate/
```

### Port already in use

LockState n'ouvre pas de port. Vérifiez les autres processus :

**Linux** : `netstat -tlnp | grep LISTEN`
**Windows** : `netstat -ano | findstr LISTEN`
**macOS** : `lsof -i -P -n`

### Rapport vide

- Vérifiez les droits d'accès sur les répertoires scannés
- Augmentez le timeout : `--timeout 60`
- Regardez les logs : `lockstate --mode quick 2>&1 | tee debug.log`

---

## 📞 Besoin d'aide ?

- 📖 [Documentation complète](docs/)
- 💬 [Discussions](https://github.com/KADOHACK12/lockstate/discussions)
- 🐛 [Issues](https://github.com/KADOHACK12/lockstate/issues)
- 🔐 [Rapport de sécurité](SECURITY.md)

---

## 📊 Cas d'usage

### Pour les administrateurs système

```bash
lockstate --mode standard --output ./audit-$(date +%Y%m%d).html
```

### Pour les consultants en sécurité

```bash
lockstate --mode deep --output ./rapport-client.html
```

### Intégration CI/CD

```bash
lockstate --mode quick --quiet && echo "Sécurité : ✓ OK" || echo "Sécurité : ✗ Problèmes détectés"
```

### Monitoring régulier

Utilisez un scheduler (cron, Task Scheduler Windows) :

```bash
0 2 * * * /usr/local/bin/lockstate --mode quick --output /var/reports/audit-$(date +\%Y\%m\%d).html
```

---

**Merci d'utiliser LockState ! 🔐**
