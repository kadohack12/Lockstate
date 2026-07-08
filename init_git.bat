@echo off
REM Script d'initialisation Git pour LockState
REM Utilise les outils de GitHub Desktop ou Git Bash

setlocal enabledelayedexpansion

REM Essayer de trouver Git via GitHub Desktop
set "GITHUB_DESKTOP_PATH=%USERPROFILE%\AppData\Local\GitHubDesktop\app-*\resources\app\git\cmd\git.exe"
set "GIT_PATH="

REM Chercher git.exe dans les chemins courants
for /f "delims=" %%a in ('where git 2^>nul') do set "GIT_PATH=%%a"

if defined GIT_PATH (
    echo Git trouve: !GIT_PATH!
) else (
    echo Git non trouve. Cherche via GitHub Desktop...
    for /d %%d in ("%USERPROFILE%\AppData\Local\GitHubDesktop\app-*") do (
        if exist "%%d\resources\app\git\cmd\git.exe" (
            set "GIT_PATH=%%d\resources\app\git\cmd\git.exe"
            echo Git trouve via GitHub Desktop: !GIT_PATH!
        )
    )
)

if not defined GIT_PATH (
    echo ERREUR: Git non trouve. Verifie que GitHub Desktop est correctement installe.
    pause
    exit /b 1
)

echo.
echo === Initialisation du depot Git ===
echo.

"!GIT_PATH!" init
"!GIT_PATH!" config user.name "KADOHACK12"
"!GIT_PATH!" config user.email "tresorsorkad@gmail.com"
"!GIT_PATH!" add .
"!GIT_PATH!" commit -m "Initial commit: LockState security audit tool"

echo.
echo === Depot Git initialise ===
echo.
echo Prochaine etape: Ouvrir GitHub Desktop et "Publish repository"
echo.
pause
