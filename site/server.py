from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import socket      # NOUVEAU : Pour la résolution de nom de domaine
import ipaddress   # NOUVEAU : Pour vérifier si c'est une IP

from nmap_scanner import run_nmap_scan
from auth_check import check_security_txt
from advanced_scanner import run_advanced_scan, run_whois

app = Flask(__name__, static_folder='.')
CORS(app) # Autorise les requêtes depuis n'importe quelle origine (ex: file://)

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

@app.route('/api/check_auth')
def api_check_auth():
    target = request.args.get('target')
    if not target:
        return jsonify({"error": "Missing target"}), 400
    
    result = check_security_txt(target)
    return jsonify(result)

@app.route('/api/scan')
def api_scan():
    target = request.args.get('target')
    advanced = request.args.get('advanced') == 'true'
    
    if not target:
        return jsonify({"error": "Missing target"}), 400
        
    # --- DÉBUT DU MÉCANISME DE REVERSE DNS ---
    scan_target = target
    try:
        # 1. On vérifie si l'utilisateur a rentré une adresse IP mathématique valide
        ipaddress.ip_address(target)
        try:
            # 2. C'est une IP : on interroge les serveurs DNS pour trouver le nom de domaine caché
            hostname, _, _ = socket.gethostbyaddr(target)
            print(f"[*] Reverse DNS : L'IP {target} a été automatiquement résolue en {hostname}")
            scan_target = hostname # On remplace l'IP par le vrai nom de domaine !
        except socket.herror:
            print(f"[*] Reverse DNS : Aucun domaine public trouvé pour l'IP {target} (VM locale ?). On conserve l'IP.")
    except ValueError:
        # Ce n'est pas une IP (ex: google.com), on ne modifie rien
        pass
    # --- FIN DU MÉCANISME ---
    
    try:
        # IMPORTANT : On utilise 'scan_target' (le nom de domaine trouvé) au lieu de 'target'
        results = run_nmap_scan(scan_target, is_advanced=advanced)
        
        # En mode normal, on ajoute Whois pour l'énumération de base
        if not advanced:
            print(f"[*] Lancement Whois (Mode Normal) pour {scan_target}...")
            results["whois_result"] = run_whois(scan_target)

        # En mode avancé, on ajoute les résultats des autres outils OFFENSIFS
        if advanced:
            print(f"[*] Lancement des outils d'audit avancés pour {scan_target}...")
            ext_results = run_advanced_scan(scan_target)
            results["external_tools"] = ext_results
            
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("[*] Serveur backend AuditSphere démarré sur http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)