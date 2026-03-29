import subprocess
import sys
import json
import xml.etree.ElementTree as ET
import ipaddress

def is_local_network(target):
    """Vérifie si la cible est sur un réseau local ou est une adresse de boucle locale (loopback)."""
    if target.lower() == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(target)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False

def run_nmap_scan(target, is_advanced=False):
    """
    Lance un scan Nmap sur la cible spécifiée et retourne les résultats au format JSON.
    Nécessite que l'outil Nmap soit installé sur le système.
    """
    print(f"[*] Démarrage du scan Nmap sur : {target}...\n")
    
    # Configuration des options Nmap (Niveau BUT 2 R&T) :
    # -sV : Active la détection de version des services en ouvrant des sockets (indispensable pour trouver les CVEs associées)
    # --script vuln : Lance les scripts NSE (Nmap Scripting Engine) pour détecter les failles connues
    # -Pn : Ne fait pas de ping ICMP préalable (très utile si le pare-feu de la cible drop les ICMP Echo Request)
    # -T5 : Mode "Insane", scan extrêmement rapide et agressif. En production réelle, on privilégiera -T3 ou -T4
    # --max-retries 1 : On ne retransmet qu'une seule fois le paquet TCP SYN si on n'a pas de ACK (gagne du temps)
    # --min-parallelism 10 : Maintient au moins 10 connexions simultanées en permanence
    # --min-rate 1000 : Envoie au minimum 1000 paquets réseaux par seconde
    # -oX - : Exporte le résultat au format XML et l'envoie sur la sortie standard (stdout) pour être lu par Python
    
   # 1. Stratégie de scan optimisée pour la fiabilité
    if target.lower() in ["localhost", "127.0.0.1", "::1"]:
        print("[*] Loopback détecté : scan rapide sans détection de failles.\n")
        command = [
            "nmap", "-Pn", "-T4", "-sT", "--disable-arp-ping", "-F", "-oX", "-"
        ]
    else:
        # Mode avancé : scan complet AVEC détection de vulnérabilités
        # On retire les contraintes de temps pour laisser les scripts "vuln" travailler correctement.
        if is_advanced:
            print("[*] Mode Avancé activé : Scan complet avec détection de vulnérabilités (--script vuln,http-enum)")
            command = [
                "nmap", "-sV", "--script", "vuln,http-enum",
                "-Pn", "-T4", "-oX", "-"
            ]
            
        # Mode normal : scan enrichi avec scripts ciblés
        # On scanne les 1000 ports par défaut (plus fiable que 5000 avec des timeout) et on garde le -T4
        else:
            print("[*] Mode Rapide activé : Top 1000 ports + batterie de scripts ciblés")
            command = [
                "nmap", "--top-ports", "1000", "-sV", "-T4",
                "--script", (
                    "banner,"
                    "ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-dh-params,"
                    "http-headers,http-enum,http-methods,http-auth-finder,"
                    "http-cookie-flags,http-cors,http-trace,http-shellshock,"
                    "ssh-hostkey,ssh-auth-methods,"
                    "ftp-anon,ftp-bounce,"
                    "smtp-commands,smtp-open-relay,"
                    "dns-zone-transfer"
                ),
                "-Pn", "-oX", "-"
            ]

        # Si on scanne une IP de notre propre LAN (réseau privé)
        if is_local_network(target):
            print("[*] Réseau local détecté : ajout restrictions arp/ping\n")
            command.extend(["-sT", "--disable-arp-ping"])
            
    command.append(target)
    
    try:
        # Exécution de la commande Nmap dans le système Linux/Windows
        # capture_output=True permet de garder le résultat XML en mémoire (dans result.stdout) plutôt que de l'afficher
        # text=True convertit les flux binaires (octets) en chaînes de caractères lisibles
        # check=True va déclencher une exception (erreur) si Nmap crash ou ne se lance pas (Code retour != 0)
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        xml_output = result.stdout
        
        # 2. Lecture du format XML renvoyé par Nmap avec ElementTree
        root = ET.fromstring(xml_output)
        
        open_ports_list = []
        scan_data = {
            "target": target,
            "status": "up",
            "open_ports": open_ports_list
        }
        
        # Vérifier si l'hôte est considéré comme "Up" (actif) par Nmap
        host = root.find("host")
        if host is None:
            scan_data["status"] = "down"
            return scan_data
            
        # 3. Parcourir tous les ports de la réponse réseau
        ports_list = host.find("ports")
        if ports_list is not None:
            for port in ports_list.findall("port"):
                state_element = port.find("state")
                
                # On récupère l'état du port (open, closed, filtered) de manière très décomposée
                if state_element is not None:
                    state = state_element.get("state")
                else:
                    state = "unknown"
                
                # On ne traite que les ports avec une socket ouverte ("open")
                if state == "open":
                    port_id = port.get("portid")
                    if port_id is not None:
                        port_id_int = int(port_id)
                    else:
                        port_id_int = 0
                        
                    protocol = port.get("protocol")
                    if protocol is None:
                        protocol = "tcp"
                    
                    # On cherche la balise XML <service> pour voir ce qui tourne (ex: Apache, sshd)
                    service_info = port.find("service")
                    service_name = "Inconnu"
                    product = ""
                    version = ""
                    
                    if service_info is not None:
                        # Extractions sécurisées (gestion des valeurs nulles)
                        name_val = service_info.get("name")
                        if name_val is not None:
                            service_name = name_val
                            
                        prod_val = service_info.get("product")
                        if prod_val is not None:
                            product = prod_val
                            
                        ver_val = service_info.get("version")
                        if ver_val is not None:
                            version = ver_val
                    
                    # 4. Parcourir et extraire les failles trouvées par les scripts NSE (--script)
                    script_results = []
                    for script in port.findall("script"):
                        script_id = script.get("id")
                        if script_id is None:
                            script_id = "unknown"
                            
                        output_text = script.get("output")
                        if output_text is not None:
                            safe_output = output_text.strip()
                        else:
                            safe_output = ""
                            
                        script_results.append({
                            "script_id": script_id,
                            "output": safe_output
                        })

                    # On ajoute le port scanné de manière propre dans notre liste finale
                    # On assemble la chaine produit/version pour faire propre
                    product_details = str(product) + " " + str(version)
                    product_details = product_details.strip()

                    open_ports_list.append({
                        "port": port_id_int,
                        "protocol": protocol,
                        "state": state,
                        "service": service_name,
                        "product_details": product_details,
                        "vulnerabilities": script_results
                    })
                    
        return scan_data

    except FileNotFoundError:
        print("[-] ERREUR CRITIQUE : Nmap n'est pas installé ou n'est pas reconnu par le système.")
        print("    Veuillez télécharger et installer Nmap (https://nmap.org/download.html)")
        print("    et vous assurer qu'il a été ajouté à vos variables d'environnement (PATH).")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[-] ERREUR Nmap (Code {e.returncode}).")
        print(e.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[-] Erreur inattendue de Python : {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Ce bloc est exécuté uniquement si on lance spécifiquement le fichier python
    
    # Vérifier que l'utilisateur a bien fourni une cible
    if len(sys.argv) < 2:
        print("Utilisation : python nmap_scanner.py <URL_OU_IP_CIBLE>")
        print("Exemples    : python nmap_scanner.py 127.0.0.1")
        print("              python nmap_scanner.py google.com")
        sys.exit(1)
        
    target_arg = sys.argv[1]
    
    # Lancement du script
    results = run_nmap_scan(target_arg)
    
    # Affichage JSON formaté (pratique si vous voulez par la suite lire ça avec un backend Node.js, PHP, etc.)
    print("[+] Analyse terminée. Résultat :\n")
    print(json.dumps(results, indent=4, ensure_ascii=False))
