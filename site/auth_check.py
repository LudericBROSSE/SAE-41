import requests  # type: ignore[import]  # Pyre2 ne trouve pas le package mais il est bien installé
from urllib.parse import urlparse
import ipaddress

def is_local_network(target):
    """Vérifie si la cible est sur un réseau local ou est une adresse de boucle locale."""
    if target.lower() in ["localhost", "127.0.0.1", "::1"]:
        return True
    try:
        ip = ipaddress.ip_address(target)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False

def check_security_txt(target):
    """
    Vérifie si la cible possède un fichier security.txt (RFC 9116)
    indiquant potentiellement une politique de divulgation de vulnérabilités
    et l'autorisation implicite ou explicite de scanner.
    """
    # Nettoyer l'URL/IP cible
    if target.startswith('http'):
        parsed = urlparse(target)
        hostname = parsed.hostname
    else:
        hostname = target.split('/')[0]

    # Bypass l'autorisation pour les cibles locales (Docker, réseau privé, localhost)
    if is_local_network(hostname):
        return {
            "authorized": True,
            "reason": "Cible identifiée comme Locale/Privée. Autorisation implicite accordée pour les tests internes.",
            "url": "Bypass (IP Privée)"
        }

    # --- Whitelist des sites de test officiels ---
    # Ces hôtes ont été mis en place EXPLICITEMENT pour être scannés librement.
    # scanme.nmap.org : site officiel Nmap pour tester ses scans (https://nmap.org/book/man-host-discovery.html)
    # hackthebox.com  : plateforme de hacking éthique (machines vulnérables intentionnelles)
    AUTHORIZED_TEST_HOSTS = [
        "scanme.nmap.org",
        "64.13.134.52",   # IP publique de scanme.nmap.org
        "hackthebox.com",
        "www.hackthebox.com",
    ]
    if hostname and hostname.lower() in AUTHORIZED_TEST_HOSTS:
        return {
            "authorized": True,
            "reason": f"Hôte de test officiel reconnu ({hostname}). Scan autorisé explicitement par l'administrateur du site.",
            "url": f"Whitelist interne AuditSphere"
        }

    # Endroits standards où trouver le fichier security.txt
    paths = [
        f"https://{hostname}/.well-known/security.txt",
        f"http://{hostname}/.well-known/security.txt",
        f"https://{hostname}/security.txt",
        f"http://{hostname}/security.txt"
    ]

    for url in paths:
        try:
            # Timeout court (1s) pour ne pas bloquer l'UI si le site est lent ou down
            response = requests.get(url, timeout=1, allow_redirects=True, verify=False)
            
            # Vérifier qu'on a bien reçu un fichier texte et pas une page HTML 404 customisée
            if response.status_code == 200 and 'Contact:' in response.text and '<html' not in response.text.lower()[:50]:
                return {
                    "authorized": True, 
                    "reason": "Fichier security.txt détecté", 
                    "url": url,
                    "content_preview": response.text[:200]
                }
        except requests.RequestException:
            # En cas d'erreur de connexion, timeout, SSL error, on teste l'URL suivante
            continue
    
    return {
        "authorized": False, 
        "reason": "Aucun fichier security.txt standard n'a été détecté pour valider l'autorisation de scan."
    }
