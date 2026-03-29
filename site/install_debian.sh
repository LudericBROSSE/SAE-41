#!/bin/bash

echo "[*] Mise à jour des dépôts Debian..."
sudo apt update

echo "[*] Installation des paquets de base (Nmap, SQLMap, WhatWeb, etc)..."
# exiftool est souvent requis en backend par PyMeta pour analyser les documents
sudo apt install -y nmap sqlmap whatweb git npm python3-pip wget curl libimage-exiftool-perl

echo "[*] Installation de Lighthouse via NPM..."
# Lighthouse nécessite Node.js/NPM
sudo npm install -g lighthouse

echo "[*] Installation de GitLeaks..."
# Il est préférable de télécharger la version compilée récente sur Github car les dépôts apt sont souvent en retard
GITLEAKS_VERSION="8.18.2"
wget "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" -O gitleaks.tar.gz
tar -zxvf gitleaks.tar.gz gitleaks
sudo mv gitleaks /usr/local/bin/
rm gitleaks.tar.gz

echo "[*] Installation de PyMeta..."
# PyMeta OSINT s'installe généralement via pip
# --break-system-packages est souvent nécessaire sur les Debian/Kali récentes si on n'utilise pas d'environnement virtuel
pip3 install pymeta --break-system-packages || pip3 install git+https://github.com/m8sec/pymeta.git --break-system-packages

# L'API Python Flask et ses dépendances
echo "[*] Installation des librairies Python pour le serveur AuditSphere..."
pip3 install flask flask-cors requests --break-system-packages

echo "[✔] Installation terminée ! Vous pouvez lancer le serveur avec : python3 server.py"
