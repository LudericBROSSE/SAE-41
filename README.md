# 🌐 AuditSpher

> **L'audit de cybersécurité automatisé, lisible et actionnable.**
> *Projet réalisé dans le cadre de la SAE 4.01 - IUT Nice Côte d'Azur.*

![Badge License](https://img.shields.io/badge/License-Open_Source-blue.svg)
![Badge Status](https://img.shields.io/badge/Status-En_développement-orange.svg)

## 🎯 À propos du projet

**AuditSpher** est une plateforme SaaS d'orchestration de scans de vulnérabilités. 
Le constat est simple : les outils de cybersécurité Open-Source sont puissants mais génèrent des rapports bruts illisibles pour les non-initiés, tandis que les solutions professionnelles sont souvent hors de prix. 

AuditSpher se positionne comme le compromis parfait : notre **Orchestrateur Central** lance de multiples outils reconnus, analyse leurs logs, et traduit ces données techniques complexes en un **Score de Sécurité global (de 0 à 100%)** inspiré des recommandations de l'ANSSI. L'outil est pensé pour les décideurs : zéro expertise technique requise pour lire le bilan de santé.

---

## ⚙️ Architecture & Fonctionnement

Notre cartographie des risques suit logiquement la construction d'une application web, répartie en **4 piliers fondamentaux**. L'orchestrateur gère ces piliers selon deux modes d'exécution :

### 🟢 Mode Normal (Scan Rapide & Non-intrusif)
* **Cible :** Audit de surface / Check de routine quotidien.
* **Avantage :** Empreinte limitée, indétectable par les pare-feux, résultat quasi instantané.
* **Outils utilisés :** Whois (Propriété), WhatWeb (Headers/Technos), Nmap bridé (Top 500 ports).

### 🔴 Mode Avancé (Audit Profond / Pentest)
* **Cible :** Recherche de failles critiques et cartographie exhaustive.
* **Avantage :** Déploiement de l'arsenal complet pour un véritable test d'intrusion automatisé.
* **Contrainte :** Temps d'exécution plus long.

---

## 🛠️ Les 4 Piliers d'Analyse (Mode Avancé)

1. **🌐 Domaine & Réseau (OSINT)**
   * *Objectif :* Détecter les fuites de données publiques et les portes dérobées.
   * *Outils :* **Sublist3r** (Énumération de sous-domaines), **PyMeta** (Extraction de métadonnées de documents publics).
2. **🖥️ Frontend & Contenus**
   * *Objectif :* S'assurer que l'interface client est saine et performante.
   * *Outils :* **WhatWeb**, **Lighthouse** (Audit d'accessibilité, de performance et de sécurité côté client).
3. **⚙️ Backend & Applicatif Web**
   * *Objectif :* Protéger la logique métier et l'intégrité du code.
   * *Outils :* **SQLmap** (Détection d'injections SQL), **GitLeaks** (Recherche de secrets, clés API ou mots de passe oubliés dans le code).
4. **🗄️ Hébergement & Infrastructure**
   * *Objectif :* Assurer la sécurité physique et logique du serveur.
   * *Outils :* **Nmap-NSE** (Nmap Scripting Engine pour la recherche active de vulnérabilités connues / CVE).

---


# Lancer l'orchestrateur
python3 server.py
