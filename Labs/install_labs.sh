#!/bin/bash

# --- Configuration ---
IP_ADDR="X.X.X.X/24"
INTERFACE="enp0s3"

echo "--- Configuration du Lab en cours ---"

# 1. Configuration de l'adresse IP
echo "[1/3] Configuration de l'IP $IP_ADDR sur $INTERFACE..."
sudo ip addr add $IP_ADDR dev $INTERFACE

# 2. Installation de Docker (Version simple pour Debian/Ubuntu/Ubuntu-like)
echo "[2/3] Installation de Docker..."
sudo apt-get update -y
sudo apt-get install -y docker.io

# 3. Lancement du service
echo "[3/3] Démarrage du service Docker..."
sudo systemctl start docker.service
sudo systemctl enable docker.service # Pour qu'il se lance au reboot

echo "--- Installation terminée avec succès ! ---"
