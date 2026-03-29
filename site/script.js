document.addEventListener('DOMContentLoaded', () => {
    // 1. Récupération de l'URL ou IP depuis les paramètres GET de index.html
    const urlParams = new URLSearchParams(window.location.search);
    let targetUrl = urlParams.get('url');
    const isAdvanced = urlParams.get('advanced') === 'on';

    // Mettre l'URL/IP dans le titre si on est sur la page des résultats
    const urlDisplay = document.getElementById('target-url-display');
    if (urlDisplay && targetUrl) {
        try {
            const domain = new URL(targetUrl.startsWith('http') ? targetUrl : 'https://' + targetUrl).hostname;
            urlDisplay.textContent = `(${domain})`;
            targetUrl = domain;
        } catch (e) {
            urlDisplay.textContent = `(${targetUrl})`;
        }
    } else if (urlDisplay) {
        urlDisplay.textContent = "(Cible Inconnue)";
        targetUrl = "Inconnu";
    }

    // Remplir le nom de domaine
    const domainDisplay = document.getElementById('domain-name-display');
    if (domainDisplay && targetUrl !== "Inconnu") {
        domainDisplay.textContent = targetUrl;
    }

    // Remplir la date (ex: 27 mars 2026 12:28)
    const dateDisplay = document.getElementById('scan-date-display');
    if (dateDisplay) {
        const now = new Date();
        const options = { day: 'numeric', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit' };
        dateDisplay.textContent = now.toLocaleDateString('fr-FR', options).replace(' à ', ' ');
    }

    // Si on est sur la page résultat, on lance la génération
    if (document.getElementById('report-content')) {
        genererRapport(targetUrl, isAdvanced);
    }
});

function calculateAnssiSeverity(impact, exploit) {
    // Si l'impact (ou exploitation) est à 0, c'est purement informatif
    if (impact === 0 || exploit === 0) {
        return "Info";
    }

    // Matrice ANSSI : X = Impact (1-4), Y = Exploitation/Difficulté (1-4)
    // Indexes: 0=Mineur/TrèsDifficile, 1=Important/Difficile, 2=Majeur/Modérée, 3=Critique/Facile
    const matrix = [
        ["Mineur", "Mineur", "Important", "Majeur"],     // Impact Mineur (1)
        ["Mineur", "Important", "Important", "Majeur"],  // Impact Important (2)
        ["Important", "Majeur", "Majeur", "Critique"],   // Impact Majeur (3)
        ["Important", "Majeur", "Critique", "Critique"]  // Impact Critique (4)
    ];
    // impact et exploit vont de 1 à 4, on soustrait 1 pour l'index du tableau
    return matrix[impact - 1][exploit - 1];
}

function getPenaltyPoints(severity) {
    // Barème de points à retirer selon la sévérité finale (ANSSI)
    const points = {
        "Info": 0,
        "Mineur": 5,
        "Important": 15,
        "Majeur": 30,
        "Critique": 45
    };
    return points[severity] || 0;
}

async function genererRapport(urlCible, isAdvanced) {
    const listElement = document.getElementById('vulnerabilities-list');
    const explanationsElement = document.getElementById('explanations-list');

    // Afficher l'état de chargement
    if (listElement) listElement.innerHTML = '<li><i class="fas fa-search"></i> Vérification des autorisations de scan en cours (security.txt)...</li>';
    if (explanationsElement) explanationsElement.innerHTML = '';

    try {
        // 1. Check Authorization first
        const authResponse = await fetch(`/api/check_auth?target=${encodeURIComponent(urlCible)}`);
        if (authResponse.ok) {
            const authData = await authResponse.json();

            if (!authData.authorized) {
                // Affiche l'écran d'erreur (Photo 1) strict
                document.getElementById('success-wrapper').style.display = 'none';
                document.querySelector('.result-title.hide-in-error').style.display = 'none';

                const errWrap = document.getElementById('error-wrapper');
                const errList = document.getElementById('error-url-list');
                if (errWrap) errWrap.style.display = 'block';

                // Construction de la liste des 403
                let baseHost = urlCible.replace(/^https?:\/\//, '');
                if (baseHost.startsWith("www.")) {
                    baseHost = baseHost.substring(4);
                }

                if (errList) {
                    errList.innerHTML = `
                        <div class="error-row"><span class="error-url">http://www.${baseHost}/</span> <span class="error-code">403</span></div>
                        <div class="error-row"><span class="error-url">https://www.${baseHost}/</span> <span class="error-code">403</span></div>
                        <div class="error-row"><span class="error-url">http://${baseHost}/</span> <span class="error-code">403</span></div>
                        <div class="error-row"><span class="error-url">https://${baseHost}/</span> <span class="error-code">403</span></div>
                    `;
                }

                const scoreDisplay = document.getElementById('score-display');
                if (scoreDisplay) scoreDisplay.innerHTML = `SCORE ANSSI : NA/100`;
                return; // On arrête l'exécution de la fonction ici, annulant l'appel vers /api/scan
            } else {
                // Autorisé via security.txt
                listElement.innerHTML = `
                    <li style="color: #00e676; margin-bottom: 15px;">
                        <i class="fas fa-check-circle"></i> Autorisation vérifiée via <code>security.txt</code> (Trouvé sur ${authData.url})
                    </li>
                    <li><i class="fas fa-spinner fa-spin"></i> Lancement de l'analyse automatique Nmap (cela peut prendre quelques minutes)...</li>`;
            }
        }
    } catch (authErr) {
        console.warn("Erreur lors de la vérification security.txt, on tente le scan Nmap", authErr);
        if (listElement) listElement.innerHTML = '<li><i class="fas fa-spinner fa-spin"></i> Impossible de vérifier le fichier security.txt. Analyse en cours par le serveur Nmap...</li>';
    }

    try {
        // --- ÉTAPE 2 : APPEL AU SERVEUR (PYTHON) POUR LANCER NMAP ---
        // Le JavaScript envoie une requête HTTP GET vers notre backend Python.
        // Le mot-clé 'await' fait patienter le code jusqu'à la fin de tout le scan.
        const response = await fetch(`/api/scan?target=${encodeURIComponent(urlCible)}&advanced=${isAdvanced}`);

        // Si le serveur a planté (erreur 500 par exemple), on déclenche une erreur manuelle
        if (response.ok === false) {
            throw new Error("Erreur serveur API locale lors du scan");
        }

        // On convertit la réponse format texte du serveur en objet JavaScript (JSON) manipulable
        const data = await response.json();

        let discoveredVulns = [];

        // Si la machine distante n'a pas répondu au ping
        if (data.status === "down") {
            listElement.innerHTML = '<li style="color: #ff3b30;">Hôte inactif ou injoignable. Le serveur semble éteint ou bloque le ping.</li>';
            return;
        }

        // --- ÉTAPE 3 : ANALYSE DES PORTS OUVERTS ---
        if (data.open_ports) {
            // On utilise une boucle 'for' classique pour parcourir tous les ports ouverts un par un
            for (let indexPort = 0; indexPort < data.open_ports.length; indexPort++) {
                let portInfo = data.open_ports[indexPort];

                // Base de sévérité par défaut "0" (Info pure = pas de pénalité) pour ne pas pénaliser un service légitime clean
                let baseImpact = 0;
                let baseExploit = 0;

                let product = "Service Inconnu";
                if (portInfo.product_details) {
                    product = portInfo.product_details;
                }

                let baseName = `Port ouvert détecté : ${portInfo.port} (${portInfo.service})`;
                let baseDesc = `Le port ${portInfo.port} est ouvert pour recevoir des connexions externes via ${product}.<br>`;

                let infoPorts = [21, 22, 25, 53, 67, 68, 69, 80, 110, 143, 443, 465, 587, 993, 995, 8080, 8443];
                let dangerPorts = [23, 139, 445, 1433, 3389, 3306, 5432, 27017]; // Telnet (23), SMB (139/445), RDP (3389), BDD (SQL/Mongo)

                // Ajustement de la gravité de base du port SELON SA NATURE
                if (infoPorts.includes(portInfo.port)) {
                    // Ports standards (Web, FTP, SFTP/SSH, DNS, DHCP, Mails...) autorisés sans pénalité de base
                    baseImpact = 0;
                    baseExploit = 0;
                    baseDesc += `<span>(Service standard autorisé sur ce port, pas de pénalité intrinsèque)</span><br>`;
                } else if (dangerPorts.includes(portInfo.port)) {
                    // Les bases de données ou les vieux protocoles exposés internet c'est très risqué : pénalité de base
                    baseImpact = 3; // Majeur
                    baseExploit = 3;
                    baseDesc += `<span>[Attention] Un service très sensible d'administration ou base de données expose le système directement sur le web !</span><br>`;
                } else {
                    // Ports bizarres inconnus : petite pénalité de base (Mineur)
                    baseImpact = 1;
                    baseExploit = 1;
                }

                // On prépare nos compteurs pour garder la PIRE (maximum) sévérité trouvée par les scripts Nmap sur ce port
                let maxImpact = baseImpact;
                let maxExploit = baseExploit;
                let scriptDetailsHTML = "";

                // Si des scripts NSE ont scanné ce port et renvoyé des résultats
                if (portInfo.vulnerabilities && portInfo.vulnerabilities.length > 0) {
                    for (let j = 0; j < portInfo.vulnerabilities.length; j++) {
                        let vuln = portInfo.vulnerabilities[j];

                        // Sécurisation vitale : Nmap recrache souvent du code HTML brut (ex: les entêtes de page 404). 
                        // Il faut absolument échapper < et > en &lt; et &gt; sinon cela casse silencieusement le DOM et html2canvas !
                        let formattedOutput = vuln.output.replace(/</g, "&lt;").replace(/>/g, "&gt;");

                        // Si le script a crashé ou n'a rien trouvé (erreur nmap courante), on saute ce script
                        if (formattedOutput.includes('Script execution failed') ||
                            formattedOutput.includes("Couldn't find") ||
                            formattedOutput.includes('ERROR:') ||
                            formattedOutput.trim() === '') {
                            continue;
                        }

                        let scriptImpact = 2; // Par défaut, une alerte script = Important (-15 pts)
                        let scriptExploit = 2;

                        if (vuln.script_id === 'vulners') {
                            const lines = vuln.output.split('\n');
                            const issues = [];

                            // On lit les lignes du module 'vulners' une par une
                            for (let k = 0; k < lines.length; k++) {
                                let parts = lines[k].trim().split(/\s+/);
                                if (parts.length >= 2) {
                                    let nameCve = parts[0];
                                    let scoreCvss = parseFloat(parts[1]);
                                    if (!isNaN(scoreCvss)) {
                                        issues.push({ full: `• ${nameCve} (Score CVSS : ${scoreCvss})`, score: scoreCvss });
                                    }
                                }
                            }

                            if (issues.length > 0) {
                                // IL N'Y A PLUS DE LIMITE (slice à 8 retiré selon la consigne), on affiche TOUTES  failles !

                                // On cherche le score CVSS (sur 10) le plus élevé de TOUTES les failles vulners
                                let maxCvss = 0;
                                for (let p = 0; p < issues.length; p++) {
                                    if (issues[p].score > maxCvss) maxCvss = issues[p].score;
                                }

                                // Conversion stricte : si CVSS >= 9 -> Critique (4), si >= 7 -> Majeur (3)...
                                if (maxCvss >= 9.0) { scriptImpact = 4; scriptExploit = 4; }
                                else if (maxCvss >= 7.0) { scriptImpact = 3; scriptExploit = 3; }
                                else if (maxCvss >= 4.0) { scriptImpact = 2; scriptExploit = 2; }
                                else { scriptImpact = 1; scriptExploit = 1; }

                                // Format d'affichage universel
                                let limit = issues.length > 10 ? 10 : issues.length;
                                let uiOutput = `Liste des failles critiques (CVE/Exploits) détectées par ${vuln.script_id} :<ul style="margin-top: 10px; margin-bottom: 0;">`;
                                for (let p = 0; p < limit; p++) {
                                    uiOutput += `<li>${issues[p].full}</li>`;
                                }
                                uiOutput += '</ul>';
                                if (issues.length > 10) {
                                    uiOutput += `<br><em>[Aperçu limité à 10 éléments. Plus de détails techniques dans le rapport PDF en version pro.]</em>`;
                                }

                                let pdfOutput = `Liste complète des failles (CVE) détectées :<ul style="margin-top: 10px; margin-bottom: 0; padding-left: 0; list-style-type: none; overflow-wrap: anywhere; word-break: break-word;">`;
                                for (let p = 0; p < issues.length; p++) {
                                    let safeText = issues[p].full.substring(2).replace('(Score CVSS :', '<span style="white-space: nowrap;">(Score CVSS :').replace(')', ')</span>');
                                    pdfOutput += `<li style="display: block; margin-bottom: 8px; line-height: 1.5; page-break-inside: avoid; break-inside: avoid;">• ${safeText}</li>`;
                                }
                                pdfOutput += '</ul>';

                                formattedOutput = `<div class="hide-in-pdf">${uiOutput}</div><div class="show-in-pdf-only" style="display: none;">${pdfOutput}</div>`;
                            }
                        }

                        // On empile la vue graphique du script dans notre bloc global
                        if (vuln.script_id !== 'vulners') {
                            let scriptLines = formattedOutput.split('\n');
                            let limitedDisplay = formattedOutput;
                            if (scriptLines.length > 10) {
                                limitedDisplay = scriptLines.slice(0, 10).join('\n') + '\n\n[... Résumé limité à 10 lignes ...]';
                            }
                            let uiOutput = `<details style="margin-top:10px;"><summary style="cursor:pointer; color:#cca8ff; font-weight:bold;">Voir les détails techniques (Script: ${vuln.script_id} - Avancé)</summary><pre style="background:#222;color:#eee;padding:10px;border-radius:5px;font-size:0.85rem;overflow-x:auto;white-space:pre-wrap;margin-top:10px;">${limitedDisplay}</pre></details>`;
                            let pdfOutput = `<div style="margin-top:10px; page-break-inside: avoid;"><strong>Détails techniques (Script: ${vuln.script_id}) :</strong><pre style="background:#f8f9fa; color:#333; padding:10px; border:1px solid #ddd; font-size:0.8rem; white-space:pre-wrap; word-break:break-word;">${formattedOutput}</pre></div>`;
                            formattedOutput = `<div class="hide-in-pdf">${uiOutput}</div><div class="show-in-pdf-only" style="display: none;">${pdfOutput}</div>`;
                        } else {
                            scriptDetailsHTML += `<br><br><b>Scanner (${vuln.script_id}) :</b><br>${formattedOutput}`;
                            // Si c'est vulners, le formatage est déjà géré juste au dessus, on ne fait pas de balise <details>
                            formattedOutput = "";
                        }

                        if (formattedOutput !== "") {
                            scriptDetailsHTML += `${formattedOutput}`;
                        }

                        // Mise à jour magique de la pire sévérité ! Si un script trouve un truc de niveau 4, tout le port passe de niveau 0 à 4.
                        if (scriptImpact > maxImpact) maxImpact = scriptImpact;
                        if (scriptExploit > maxExploit) maxExploit = scriptExploit;

                    } // Fin de la boucle des failles (script NSE)
                }

                // --- AJOUT GLOBAL DANS LE TABLEAU POUR LA PAGE ---
                // On met l'Alerte au propre. ON A QU'UNE SEULE CARTE (1 box) PAR PORT avec tous ses détails à l'intérieur !
                if (scriptDetailsHTML !== "") {
                    baseDesc += `<br><br><b>Logs d'audit combinés pour ce port :</b>${scriptDetailsHTML}`;
                }

                // On n'ajoute la faille que si le port est jugé non neutre (maxImpact > 0)
                // Ou bien si on veut afficher TOUS les ports on l'ajoute quand même pour faire "Info"
                discoveredVulns.push({
                    name: baseName,
                    impact: maxImpact,
                    exploit: maxExploit,
                    desc: baseDesc
                });

            } // Fin de la boucle for(indexPort) sur open_ports
        }

        // --- ÉTAPE 3b : ANALYSE DES PORTS DANGEREUX (Mode Rapide) ---
        // En mode rapide, on n'a pas --script vuln. On calcule quand même un score
        // pertinent en appliquant des pénalités selon les services exposés.
        if (!isAdvanced && data.open_ports) {
            // Table des ports à risque : port → {nom, impact, exploit, sévérité, description}
            const RISKY_PORTS = {
                21: { name: "FTP", impact: 3, exploit: 3, sev: "Important", desc: "FTP (port 21) est un protocole non chiffré. Les identifiants transitent en clair. À remplacer par SFTP ou FTPS." },
                23: { name: "Telnet", impact: 4, exploit: 4, sev: "Critique", desc: "Telnet (port 23) transmet toutes les données en clair, y compris les mots de passe. Protocole obsolète à désactiver immédiatement." },
                25: { name: "SMTP", impact: 2, exploit: 2, sev: "Mineur", desc: "SMTP (port 25) ouvert publiquement peut être exploité pour du spam ou de l'énumération d'utilisateurs." },
                110: { name: "POP3", impact: 2, exploit: 2, sev: "Mineur", desc: "POP3 (port 110) sans chiffrement expose les emails en transit." },
                135: { name: "RPC", impact: 3, exploit: 3, sev: "Important", desc: "RPC (port 135) expose des services Windows distants. Souvent ciblé par des vers et des ransomwares." },
                139: { name: "NetBIOS", impact: 3, exploit: 3, sev: "Important", desc: "NetBIOS (port 139) permet l'énumération des partages réseau et des utilisateurs Windows." },
                445: { name: "SMB", impact: 4, exploit: 4, sev: "Critique", desc: "SMB (port 445) est la cible de vulnérabilités majeures (EternalBlue/WannaCry). À filtrer impérativement par un pare-feu." },
                3389: { name: "RDP", impact: 3, exploit: 4, sev: "Majeur", desc: "RDP (port 3389) exposé sur Internet est très ciblé par les attaques par force brute et BlueKeep." },
                5900: { name: "VNC", impact: 3, exploit: 3, sev: "Important", desc: "VNC (port 5900) permet un accès graphique distant. Sans chiffrement et authentification forte, c'est une porte ouverte." },
                6379: { name: "Redis", impact: 4, exploit: 4, sev: "Critique", desc: "Redis (port 6379) ouvert sans authentification permet souvent une exécution de commande à distance." },
                27017: { name: "MongoDB", impact: 4, exploit: 4, sev: "Critique", desc: "MongoDB (port 27017) sans authentification expose toutes les bases de données publiquement." },
            };

            const openPortNumbers = data.open_ports.map(p => p.port);

            for (const [portNum, info] of Object.entries(RISKY_PORTS)) {
                if (openPortNumbers.includes(parseInt(portNum))) {
                    discoveredVulns.push({
                        name: `[Mode Rapide] Service risqué exposé : ${info.name} (port ${portNum})`,
                        severity: info.sev,
                        impact: info.impact,
                        exploit: info.exploit,
                        desc: `<strong>Détecté par analyse des ports (sans scripts NSE).</strong><br>${info.desc}<br><em>Passez en Mode Avancé pour une analyse approfondie de cette vulnérabilité.</em>`
                    });
                }
            }
        }

        // --- ÉTAPE 3c : AFFICHAGE WHOIS (Mode Normal) ---
        if (!isAdvanced && data.whois_result) {
            const whois = data.whois_result;
            if (whois.status === "success" && whois.output && whois.output.trim().length > 0) {
                // On extrait les lignes clés du whois (registrar, dates, nameservers)
                const lines = whois.output.split('\n');
                const keywords = ['registrar', 'creation date', 'updated date', 'expiry date', 'name server', 'registrant', 'tech email', 'org'];
                const keyLines = lines.filter(l => keywords.some(k => l.toLowerCase().includes(k))).slice(0, 12);
                const keyOutput = keyLines.length > 0 ? keyLines.join('\n') : whois.output.split('\n').slice(0, 12).join('\n');

                let uiWhois = `<details style="margin-top:10px;"><summary style="cursor:pointer; color:#cca8ff; font-weight:bold;">Voir les données Whois</summary><pre style="background:#222;color:#eee;padding:10px;border-radius:5px;font-size:0.85rem;overflow-x:auto;white-space:pre-wrap;margin-top:10px;">${keyOutput}</pre></details>`;
                let pdfWhois = `<div style="margin-top:10px; page-break-inside: avoid;"><strong>Données Whois :</strong><pre style="background:#f8f9fa; color:#333; padding:10px; border:1px solid #ddd; font-size:0.8rem; white-space:pre-wrap; word-break:break-word;">${keyOutput}</pre></div>`;
                let finalWhois = `<div class="hide-in-pdf">${uiWhois}</div><div class="show-in-pdf-only" style="display: none;">${pdfWhois}</div>`;

                discoveredVulns.push({
                    name: "Informations WHOIS publiques (Outil: Whois)",
                    impact: 0, exploit: 0, // Info pure, pas de pénalité
                    desc: `Les données d'enregistrement du domaine sont publiquement accessibles. Ces informations (registrar, dates d'expiration, serveurs DNS) peuvent être exploitées pour de la reconnaissance offensive.<br>${finalWhois}`
                });
            } else if (whois.status === "missing") {
                console.info("Whois non installé sur le serveur.");
            }
        }

        // --- ÉTAPE 4 : LECTURE DES OUTILS EXTERNES MULTIPLES (Mode Avancé) ---
        if (data.external_tools) {
            const ext = data.external_tools;
            // Process SQLMap
            if (ext.sqlmap && ext.sqlmap.status === "success") {
                let sqlOut = ext.sqlmap.output;

                // Nettoyage de la bannière illisible de SQLMap (on coupe tout avant le lancement réel)
                let sqlStart = sqlOut.indexOf('[*] starting');
                if (sqlStart !== -1) sqlOut = sqlOut.substring(sqlStart);

                // Suppression des lignes de questions interactives automatisées (--batch)
                sqlOut = sqlOut.split('\n').filter(line => !line.includes('[y/N]') && !line.includes('[Y/n]')).join('\n');

                let limitedSqlOut = sqlOut.split('\n').slice(0, 10).join('\n');
                if (sqlOut.split('\n').length > 10) limitedSqlOut += '\n\n[... Résumé limité à 10 lignes ...]';

                let uiSqlProof = `<details style="margin-top:10px;"><summary style="cursor:pointer; color:#cca8ff; font-weight:bold;">Voir les logs (Avancé)</summary><pre style="background:#222;color:#eee;padding:10px;border-radius:5px;font-size:0.85rem;overflow-x:auto;white-space:pre-wrap;margin-top:10px;">${limitedSqlOut}</pre></details>`;
                let pdfSqlProof = `<div style="margin-top:10px; page-break-inside: avoid;"><strong>Logs complets SQLMap :</strong><pre style="background:#f8f9fa; color:#333; padding:10px; border:1px solid #ddd; font-size:0.8rem; white-space:pre-wrap; word-break:break-word;">${sqlOut}</pre></div>`;
                let finalSqlOut = `<div class="hide-in-pdf">${uiSqlProof}</div><div class="show-in-pdf-only" style="display: none;">${pdfSqlProof}</div>`;

                let isTrueNegative = sqlOut.includes("all tested parameters do not appear to be injectable") ||
                    sqlOut.includes("[CRITICAL]") ||
                    sqlOut.includes("Connection refused") ||
                    sqlOut.includes("no usable links found") ||
                    sqlOut.includes("unable to connect");

                if (sqlOut.includes("is vulnerable") || sqlOut.includes("identified the following injection") || sqlOut.includes("Parameter:")) {
                    discoveredVulns.push({
                        name: "Injection SQL confirmée (Outil: SQLMap)",
                        impact: 4, exploit: 4, // CRITIQUE (45 pts)
                        desc: `L'outil SQLMap a prouvé qu'une injection SQL aveugle ou basée sur les erreurs est possible sur la cible. C'est une faille critique !<br>${finalSqlOut}`
                    });
                } else if (!isTrueNegative && sqlOut.trim().length > 0) {
                    discoveredVulns.push({
                        name: "Alerte de sécurité Base de Données (Outil: SQLMap)",
                        impact: 2, exploit: 2, // IMPORTANT (15 pts)
                        desc: `SQLMap a rencontré un comportement suspect ou n'a pas pu terminer le scan proprement. Vérifiez manuellement les entrées utilisateur.<br>${finalSqlOut}`
                    });
                }
            }
            // Process Lighthouse
            if (ext.lighthouse && ext.lighthouse.status === "success" && ext.lighthouse.scores) {
                let scores = ext.lighthouse.scores;
                if (scores["best-practices"] !== undefined && scores["best-practices"] < 80) {
                    discoveredVulns.push({
                        name: `Mauvaises pratiques Web (Outil: Lighthouse, Score: ${scores["best-practices"]}/100)`,
                        impact: 2, exploit: 1, // IMPORTANT (-15 pts)
                        desc: `L'audit Lighthouse indique un faible score de bonnes pratiques web sécurisées. Cela inclut souvent l'absence de HTTPS, des en-têtes CSP mal configurés ou des librairies JS obsolètes contenant des failles connues.`
                    });
                }
            }
            // Process WhatWeb
            if (ext.whatweb && ext.whatweb.status === "success") {
                let wwOut = ext.whatweb.output;
                let limitedWwOut = wwOut.split('\n').slice(0, 10).join('\n');
                if (wwOut.split('\n').length > 10) limitedWwOut += '\n\n[... Résumé limité à 10 lignes ...]';

                let uiWw = `<details style="margin-top:10px;"><summary style="cursor:pointer; color:#cca8ff; font-weight:bold;">Voir les détails (Avancé)</summary><pre style="background:#222;color:#eee;padding:10px;border-radius:5px;font-size:0.85rem;overflow-x:auto;white-space:pre-wrap;margin-top:10px;">${limitedWwOut}</pre></details>`;
                let pdfWw = `<div style="margin-top:10px; page-break-inside: avoid;"><strong>Détails techniques :</strong><pre style="background:#f8f9fa; color:#333; padding:10px; border:1px solid #ddd; font-size:0.8rem; white-space:pre-wrap; word-break:break-word;">${wwOut}</pre></div>`;
                let finalWw = `<div class="hide-in-pdf">${uiWw}</div><div class="show-in-pdf-only" style="display: none;">${pdfWw}</div>`;

                if (wwOut.trim().length > 0 && !wwOut.includes("Unrecognized")) {
                    discoveredVulns.push({
                        name: "Empreinte Technologique exposée (Outil: WhatWeb)",
                        impact: 1, exploit: 2, // MINEUR (-5 pts)
                        desc: `L'énumérateur WhatWeb a identifié avec précision les technologies (Serveur, CMS, Langages) du site. Trop de détails visibles aident les attaquants à trouver la faille correspondante :<br>${finalWw}`
                    });
                }
            }
            // Process PyMeta
            if (ext.pymeta && ext.pymeta.status === "success") {
                let pmOut = ext.pymeta.output;
                let limitedPmOut = pmOut.split('\n').slice(0, 10).join('\n');
                if (pmOut.split('\n').length > 10) limitedPmOut += '\n\n[... Résumé limité à 10 lignes ...]';

                let uiPm = `<details style="margin-top:10px;"><summary style="cursor:pointer; color:#cca8ff; font-weight:bold;">Voir les données extraites (Avancé)</summary><pre style="background:#222;color:#eee;padding:10px;border-radius:5px;font-size:0.85rem;overflow-x:auto;white-space:pre-wrap;margin-top:10px;">${limitedPmOut}</pre></details>`;
                let pdfPm = `<div style="margin-top:10px; page-break-inside: avoid;"><strong>Données extraites :</strong><pre style="background:#f8f9fa; color:#333; padding:10px; border:1px solid #ddd; font-size:0.8rem; white-space:pre-wrap; word-break:break-word;">${pmOut}</pre></div>`;
                let finalPm = `<div class="hide-in-pdf">${uiPm}</div><div class="show-in-pdf-only" style="display: none;">${pdfPm}</div>`;

                if (pmOut.includes("Author:") || pmOut.includes("Creator:") || pmOut.includes("Producer:")) {
                    discoveredVulns.push({
                        name: "Fuite de métadonnées internes (Outil: PyMeta)",
                        impact: 2, exploit: 2, // IMPORTANT (-15 pts)
                        desc: `Des métadonnées ont été extraites de documents publics (.pdf, .docx) sur le serveur. Ces données sensibles dévoilent des noms d'utilisateurs internes, logiciels systèmes ou répertoires cachés (Exif/XMP).<br>${finalPm}`
                    });
                }
            }
            // Process GitLeaks
            if (ext.gitleaks && ext.gitleaks.status === "success") {
                let glOut = ext.gitleaks.output;
                let limitedGlOut = glOut.split('\n').slice(0, 10).join('\n');
                if (glOut.split('\n').length > 10) limitedGlOut += '\n\n[... Résumé limité à 10 lignes ...]';

                let uiGl = `<details style="margin-top:10px;"><summary style="cursor:pointer; color:#cca8ff; font-weight:bold;">Voir les secrets (Avancé)</summary><pre style="background:#222;color:#eee;padding:10px;border-radius:5px;font-size:0.85rem;overflow-x:auto;white-space:pre-wrap;margin-top:10px;">${limitedGlOut}</pre></details>`;
                let pdfGl = `<div style="margin-top:10px; page-break-inside: avoid;"><strong>Secrets détectés :</strong><pre style="background:#f8f9fa; color:#333; padding:10px; border:1px solid #ddd; font-size:0.8rem; white-space:pre-wrap; word-break:break-word;">${glOut}</pre></div>`;
                let finalGl = `<div class="hide-in-pdf">${uiGl}</div><div class="show-in-pdf-only" style="display: none;">${pdfGl}</div>`;

                if (glOut.includes("leaks found") || glOut.includes("commit")) {
                    discoveredVulns.push({
                        name: "Fuite de clés secrètes/Tokens (Outil: GitLeaks)",
                        impact: 4, exploit: 4, // CRITIQUE (-45 pts)
                        desc: `GitLeaks a détecté des secrets codés en dur (mots de passe, clés API AWS, tokens Stripe) divulgués publiquement via des dépôts exposés ou des fichiers de configuration sur le serveur.<br>${finalGl}`
                    });
                }
            }
        }

        if (discoveredVulns.length === 0) {
            discoveredVulns.push({
                name: "Aucune vulnérabilité évidente détectée",
                impact: 1, exploit: 1,
                desc: "Le scan n'a trouvé aucune faille grave ni port critique exposé. L'application résiste aux tests du Mode Avancé fournis par Nmap, SQLMap, etc."
            });
        }

        // --- ÉTAPE 5 : CALCUL DU SCORE GLOBAL ANSSI ---
        // Le score part de 100 points maximum pour un audit parfait.
        let score = 100;

        // On crée un tableau (Array simple) pour se rappeler du nom des failles déjà pénalisées.
        // Ça évite d'enlever 2 fois 45 points si la même faille web est trouvée 2 fois sur des pages différentes.
        let nomsDesFaillesDejaVues = [];

        // On crée notre nouveau tableau de travail
        let faillesGravesCalculees = [];

        // On repasse sur les failles trouvées pour déterminer les points en moins
        for (let i = 0; i < discoveredVulns.length; i++) {
            let vuln = discoveredVulns[i];

            // On calcule la catégorie globale (Critique, Majeur, Mineur...) selon le duo d'Impact et d'Exploitation
            let severity = calculateAnssiSeverity(vuln.impact, vuln.exploit);

            // On récupère le nombre de points à retirer
            let penalty = getPenaltyPoints(severity);

            // "includes()" vérifie si on a déjà traité ce nom précis :
            let failleDejaComptee = nomsDesFaillesDejaVues.includes(vuln.name);

            if (failleDejaComptee === true) {
                penalty = 0; // Si déjà puni, on ne retire plus de points (Pénalité à 0) !
            } else {
                // Sinon, c'est nouveau. On l'enregistre dans nos archives pour la prochaine fois
                nomsDesFaillesDejaVues.push(vuln.name);
                // On met à jour le score global
                score = score - penalty;
            }

            // On greffe manuellement les valeurs dans l'objet pour s'en resservir à l'affichage
            vuln.severity = severity;
            vuln.penalty = penalty;
            faillesGravesCalculees.push(vuln);
        }

        // On met au plancher le score : pas de notes négatives
        if (score < 1) {
            score = 1;
        }

        // On remplace l'ancienne liste par la liste avec toutes les pénalités définitives
        discoveredVulns = faillesGravesCalculees;

        // --- ÉTAPE 6 : AFFICHAGE VISUEL SUR LA PAGE (DOM) ---
        const scoreDisplay = document.getElementById('score-display');
        const centerScore = document.getElementById('center-score');
        const donutChart = document.getElementById('score-chart');

        // Setup Tools Display
        const toolsUsedDisplay = document.getElementById('tools-used-display');
        const toolsListSpan = document.getElementById('tools-list');
        if (toolsUsedDisplay && toolsListSpan) {
            let toolsList = ["Nmap", "Nmap-NSE"];
            if (isAdvanced && data.external_tools) {
                if (data.external_tools.sqlmap) toolsList.push("SQLMap");
                if (data.external_tools.lighthouse) toolsList.push("Lighthouse");
                if (data.external_tools.whatweb) toolsList.push("WhatWeb");
                if (data.external_tools.pymeta) toolsList.push("PyMeta");
                if (data.external_tools.gitleaks) toolsList.push("GitLeaks");
            }
            toolsListSpan.textContent = toolsList.join(' • ');
            toolsUsedDisplay.style.display = 'block';
        }

        // Calcul dynamique et progressif de la couleur du score via HSL (Hue, Saturation, Lightness)
        let hue = Math.max(0, Math.min(120, (score * 1.2)));
        let scoreColor = `hsl(${hue}, 100%, 45%)`;

        if (centerScore) {
            centerScore.textContent = `${score}`;
            centerScore.style.color = scoreColor;
        }

        if (donutChart) {
            donutChart.style.background = `conic-gradient(${scoreColor} ${score}%, #f1f5f9 ${score}%)`;
            donutChart.dataset.scorePct = score;
            donutChart.dataset.scoreColor = scoreColor;
        }

        // --- MISE A JOUR DES BARRES DE PROGRESSION (Photo 2) ---
        let errPoints = 0;
        let warnPoints = 0;
        for (let v of discoveredVulns) {
            if (v.severity === 'Critique' || v.severity === 'Majeur') errPoints += v.penalty;
            else if (v.severity === 'Important' || v.severity === 'Mineur') warnPoints += v.penalty;
        }

        // Correct bar : Représente le score (pourcentage de réussite)
        const barCorrect = document.getElementById('bar-correct');
        if (barCorrect) barCorrect.style.width = `${score}%`;
        const pdfCorrect = document.getElementById('pdf-pct-correct');
        if (pdfCorrect) pdfCorrect.textContent = `${score}%`;

        // Warning bar : Représente les points perdus par avertissement
        let wPct = Math.min(100, (warnPoints / 45) * 100);
        const barWarn = document.getElementById('bar-warning');
        if (barWarn) barWarn.style.width = `${wPct}%`;
        const pdfWarn = document.getElementById('pdf-pct-warning');
        if (pdfWarn) pdfWarn.textContent = `${Math.round(wPct)}%`;

        // Error bar : Représente les points perdus par erreurs graves
        let ePct = Math.min(100, (errPoints / 45) * 100);
        const barErr = document.getElementById('bar-error');
        if (barErr) barErr.style.width = `${ePct}%`;
        const pdfErr = document.getElementById('pdf-pct-error');
        if (pdfErr) pdfErr.textContent = `${Math.round(ePct)}%`;

        // Score PDF text (affiché uniquement dans le PDF, même couleur que le site)
        const pdfScore = document.getElementById('pdf-score-text');
        if (pdfScore) {
            pdfScore.textContent = `${score}/100`;
            pdfScore.style.color = scoreColor;
        }

        // Ordre d'affichage des failles de la plus grave à la moins grave
        const severityOrder = { "Critique": 1, "Majeur": 2, "Important": 3, "Mineur": 4, "Info": 5 };
        discoveredVulns.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

        if (listElement && explanationsElement) {
            listElement.innerHTML = '';
            explanationsElement.innerHTML = '';

            for (let idx = 0; idx < discoveredVulns.length; idx++) {
                let v = discoveredVulns[idx];

                // On choisit la couleur de fond selon la gravité de la faille
                let colorHex = '#00e676'; // Par défaut Vert (Info pure, pas de soucis)
                if (v.severity === 'Critique') colorHex = '#333333';      // Noir (Extrême urgence)
                else if (v.severity === 'Majeur') colorHex = '#ff3b30';   // Rouge (Très grave)
                else if (v.severity === 'Important') colorHex = '#ff9500';// Orange (Grave)
                else if (v.severity === 'Mineur') colorHex = '#ffcc00';   // Jaune (Alerte minime)

                const li = document.createElement('li');
                li.innerHTML = `- <strong style="color: ${colorHex};">[${v.severity.toUpperCase()}]</strong> : ${v.name} <span style="font-size: 0.9em; color: #aaa">(-${v.penalty} pts)</span>`;
                listElement.appendChild(li);

                const explanationDiv = document.createElement('div');
                explanationDiv.className = 'explanation-item';
                // On n'utilise plus white-space: pre-wrap globalement ici car v.desc contient maintenant des balises HTML (<br>, <span>...)
                explanationDiv.innerHTML = `
                    <h4><strong style="color: ${colorHex};">[${v.severity}]</strong> ${v.name}</h4>
                    <p style="color: #cca8ff; font-size: 0.95rem; margin-bottom: 10px;">
                        Matrice ANSSI : Impact [${v.impact}/4] - Exploitation [${v.exploit}/4] ➔ Pénalité de -${v.penalty} pts.
                    </p>
                    <p style="margin-top: 15px;"><strong>En langage clair :</strong><br>${v.desc}</p>
                `;
                explanationDiv.style.borderLeftColor = colorHex;
                explanationsElement.appendChild(explanationDiv);
            }
        }

        // 5. Génération du PDF avec html2pdf.js
        bindPdfGeneration(urlCible, donutChart);

    } catch (error) {
        listElement.innerHTML = `<li style="color: #ff3b30;">Erreur : impossible de contacter le serveur backend ou erreur Nmap : ${error.message}</li>`;
        console.error(error);
    }
}

function bindPdfGeneration(urlCible, donutChart) {
    const downloadBtn = document.getElementById('download-pdf');
    if (downloadBtn) {
        const newBtn = downloadBtn.cloneNode(true);
        downloadBtn.parentNode.replaceChild(newBtn, downloadBtn);

        newBtn.addEventListener('click', () => {
            const element = document.getElementById('report-content');
            let safeName = urlCible ? urlCible.replace(/[^a-zA-Z0-9]/g, '_') : 'Scan';

            const opt = {
                margin: [10, 15, 10, 15],
                filename: `Audit_ANSSI_${safeName}.pdf`,
                image: { type: 'jpeg', quality: 1 },
                html2canvas: { scale: 2, useCORS: true, logging: false },
                jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' },
                // Évite de couper les blocs d'explications en deux au milieu d'une page
                pagebreak: { mode: ['avoid-all', 'css', 'legacy'] }
            };

            // Activer le mode impression
            element.classList.add('pdf-mode');

            // Afficher dynamiquement les éléments réservés au PDF et cacher ceux de l'écran
            document.querySelectorAll('.show-in-pdf-only').forEach(el => el.style.display = 'block');
            document.querySelectorAll('.hide-in-pdf').forEach(el => el.style.display = 'none');

            if (donutChart) {
                donutChart.style.background = `conic-gradient(${donutChart.dataset.scoreColor} ${donutChart.dataset.scorePct}%, #e0e0e0 0)`;
            }

            html2pdf().set(opt).from(element).save().then(() => {
                // Restaurer l'affichage normal
                element.classList.remove('pdf-mode');

                document.querySelectorAll('.show-in-pdf-only').forEach(el => el.style.display = 'none');
                // Attention : ne pas forcer display: block sur les éléments SVG ou spécifiques, on enlève juste le "none" inline
                document.querySelectorAll('.hide-in-pdf').forEach(el => el.style.display = '');

            }).catch(err => {
                console.error("Erreur PDF:", err);

                element.classList.remove('pdf-mode');
                document.querySelectorAll('.show-in-pdf-only').forEach(el => el.style.display = 'none');
                document.querySelectorAll('.hide-in-pdf').forEach(el => el.style.display = '');
                if (donutChart) {
                    donutChart.style.background = `conic-gradient(${donutChart.dataset.scoreColor} ${donutChart.dataset.scorePct}%, rgba(255,255,255,0.1) 0)`;
                }

                // SOLUTION DE SECOURS ABSOLUE POUR SOUTENANCE : Impression native (Ctrl+P => Sauvegarder en PDF)
                if (confirm("Le rapport complet contient tellement de vulnérabilités que la librairie d'export image a bloqué.\n\nSouhaitez-vous générer le PDF via l'outil natif de votre navigateur (garanti à 100%) ?")) {
                    element.classList.add('pdf-mode');
                    document.querySelectorAll('.show-in-pdf-only').forEach(el => el.style.display = 'block');
                    document.querySelectorAll('.hide-in-pdf').forEach(el => el.style.display = 'none');

                    window.setTimeout(() => {
                        window.print();
                        // Restauration après la fermeture de la fenêtre d'impression
                        element.classList.remove('pdf-mode');
                        document.querySelectorAll('.show-in-pdf-only').forEach(el => el.style.display = 'none');
                        document.querySelectorAll('.hide-in-pdf').forEach(el => el.style.display = '');
                    }, 500);
                }
            });
        });
    }
}
