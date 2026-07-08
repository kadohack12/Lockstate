# Script PowerShell d'initialisation Git via GitHub Desktop

$gitExe = "C:\Users\KADOHACK12\AppData\Local\GitHubDesktop\app-3.6.2\resources\app\git\cmd\git.exe"

if (-not (Test-Path $gitExe)) {
    Write-Host "Git non trouve!" -ForegroundColor Red
    exit 1
}

Write-Host "Git trouve: $gitExe" -ForegroundColor Green
Write-Host ""
Write-Host "Initialisation du depot Git" -ForegroundColor Cyan
Write-Host ""

& $gitExe init
& $gitExe config user.name "KADOHACK12"
& $gitExe config user.email "tresorsorkad@gmail.com"
& $gitExe add .
& $gitExe commit -m "Initial commit: LockState security audit tool"

Write-Host ""
Write-Host "Depot Git initialise!" -ForegroundColor Green
Write-Host ""
Write-Host "Prochaines etapes:" -ForegroundColor Cyan
Write-Host "  1. Ouvre GitHub Desktop"
Write-Host "  2. File -> Add Local Repository"
Write-Host "  3. Selectione ce dossier"
Write-Host "  4. Clique Publish repository"
Write-Host ""
