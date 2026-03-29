@echo off
chcp 65001 >nul
echo ============================================
echo   AuditSphere - Installation Windows
echo   KatreLettre - Script d'installation
echo ============================================
echo.

:: Vérification des droits administrateurs
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERREUR] Ce script doit etre execute en tant qu'Administrateur !
    echo Faites un clic droit sur le fichier .bat et choisissez "Executer en tant qu'administrateur".
    pause
    exit /b 1
)

:: ─────────────────────────────────────────────
:: 1. VÉRIFICATION DE WINGET (installeur Windows)
:: ─────────────────────────────────────────────
echo [*] Verification de winget...
winget --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERREUR] winget n'est pas disponible.
    echo Installez "App Installer" depuis le Microsoft Store et recommencez.
    pause
    exit /b 1
)
echo [OK] winget est disponible.
echo.

:: ─────────────────────────────────────────────
:: 2. NMAP
:: ─────────────────────────────────────────────
echo [*] Installation de Nmap...
winget install --id Insecure.Nmap -e --silent --accept-source-agreements --accept-package-agreements
if %errorLevel% neq 0 (
    echo [ATTENTION] Nmap n'a pas pu etre installe automatiquement.
    echo Telechargez-le manuellement : https://nmap.org/download.html
) else (
    echo [OK] Nmap installe.
)
echo.

:: ─────────────────────────────────────────────
:: 3. PYTHON 3
:: ─────────────────────────────────────────────
echo [*] Verification de Python 3...
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [*] Python introuvable. Installation via winget...
    winget install --id Python.Python.3.11 -e --silent --accept-source-agreements --accept-package-agreements
    echo [OK] Python 3 installe. Relancez ce script pour continuer.
    pause
    exit /b 0
) else (
    echo [OK] Python est deja installe.
)
echo.

:: ─────────────────────────────────────────────
:: 4. NODE.JS (requis pour Lighthouse)
:: ─────────────────────────────────────────────
echo [*] Installation de Node.js (pour Lighthouse)...
winget install --id OpenJS.NodeJS.LTS -e --silent --accept-source-agreements --accept-package-agreements
echo [OK] Node.js installe.
echo.

:: ─────────────────────────────────────────────
:: 5. SQLMAP (via pip)
:: ─────────────────────────────────────────────
echo [*] Installation de SQLMap...
pip install sqlmap
if %errorLevel% neq 0 (
    echo [ATTENTION] SQLMap n'a pas pu etre installe via pip.
    echo Telechargez-le manuellement : https://sqlmap.org
) else (
    echo [OK] SQLMap installe.
)
echo.

:: ─────────────────────────────────────────────
:: 6. WHATWEB (via gem Ruby ou Docker - optionnel)
:: ─────────────────────────────────────────────
echo [*] Tentative d'installation de WhatWeb via gem (Ruby)...
gem install whatweb >nul 2>&1
if %errorLevel% neq 0 (
    echo [INFO] WhatWeb non installe (Ruby absent ou non supporte).
    echo WhatWeb est optionnel. Il fonctionnera sans sur Windows.
) else (
    echo [OK] WhatWeb installe.
)
echo.

:: ─────────────────────────────────────────────
:: 7. LIGHTHOUSE (via npm)
:: ─────────────────────────────────────────────
echo [*] Installation de Lighthouse via NPM...
npm install -g lighthouse
if %errorLevel% neq 0 (
    echo [ATTENTION] Lighthouse n'a pas pu etre installe (NPM absent ?).
) else (
    echo [OK] Lighthouse installe.
)
echo.

:: ─────────────────────────────────────────────
:: 8. GITLEAKS (binaire Windows)
:: ─────────────────────────────────────────────
echo [*] Telechargement de GitLeaks v8.18.2 pour Windows...
set GITLEAKS_VERSION=8.18.2
set GITLEAKS_URL=https://github.com/gitleaks/gitleaks/releases/download/v%GITLEAKS_VERSION%/gitleaks_%GITLEAKS_VERSION%_windows_x64.zip
set GITLEAKS_ZIP=%TEMP%\gitleaks.zip
set GITLEAKS_DIR=%ProgramFiles%\gitleaks

powershell -Command "Invoke-WebRequest -Uri '%GITLEAKS_URL%' -OutFile '%GITLEAKS_ZIP%'"
if %errorLevel% neq 0 (
    echo [ATTENTION] Echec du telechargement de GitLeaks.
    echo Telechargez manuellement : https://github.com/gitleaks/gitleaks/releases
) else (
    mkdir "%GITLEAKS_DIR%" 2>nul
    powershell -Command "Expand-Archive -Path '%GITLEAKS_ZIP%' -DestinationPath '%GITLEAKS_DIR%' -Force"
    :: Ajout au PATH système
    setx PATH "%PATH%;%GITLEAKS_DIR%" /M >nul
    echo [OK] GitLeaks installe dans %GITLEAKS_DIR% et ajoute au PATH.
)
echo.

:: ─────────────────────────────────────────────
:: 9. LIBRAIRIES PYTHON (Flask, requests, etc.)
:: ─────────────────────────────────────────────
echo [*] Installation des librairies Python pour AuditSphere...
pip install flask flask-cors requests pymeta
if %errorLevel% neq 0 (
    echo [ATTENTION] Certaines librairies Python n'ont pas pu etre installees.
) else (
    echo [OK] Flask, requests, pymeta installes.
)
echo.

:: ─────────────────────────────────────────────
:: 10. AJOUTER NMAP AU PATH (si pas déjà fait)
:: ─────────────────────────────────────────────
echo [*] Ajout de Nmap au PATH systeme (si absent)...
setx PATH "%PATH%;C:\Program Files (x86)\Nmap" /M >nul 2>&1
echo [OK] PATH mis a jour.
echo.

echo ============================================
echo   [OK] Installation terminee !
echo ============================================
echo.
echo Pour lancer AuditSphere :
echo   1. Ouvrez un nouveau terminal (CMD ou PowerShell)
echo   2. Allez dans le dossier du projet
echo   3. Lancez : python server.py
echo.
echo NOTE : Fermez et rouvrez votre terminal pour que les
echo        nouveaux PATH soient pris en compte.
echo.
pause
