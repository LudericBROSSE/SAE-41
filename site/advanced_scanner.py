import subprocess
import json
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict

# Type alias pour la lisibilité et pour satisfaire Pyre2
ScanResult = Dict[str, Any]

def run_tool(command: list, tool_name: str) -> ScanResult:
    """Exécute une commande système en gérant les erreurs."""
    try:
        # Timeout généreux de 3 minutes par outil pour éviter que l'API plante indéfiniment
        # Passe de 180 à 300 (5 minutes) ou 600 (10 minutes)
        result = subprocess.run(command, capture_output=True, text=True, timeout=600)
        # Pyre2 type: stdout est Optional[str] en théorie, on le force en str
        stdout: str = result.stdout or ""
        return {"status": "success", "output": stdout[:2000]}  # type: ignore[index]  # slicing str est valide en Python
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": f"{tool_name} a dépassé le délai imparti."}
    except FileNotFoundError:
        return {"status": "missing", "error": f"{tool_name} n'est pas installé sur le serveur."}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def run_sqlmap(target: str) -> ScanResult:
    # SQLMap avec arguments pour scan rapide (-m batch, pas d'interactions)
    url = f"http://{target}" if not target.startswith("http") else target
    cmd = ["sqlmap", "-u", url, "--batch", "--crawl=1", "--level=1", "--risk=1"]
    return run_tool(cmd, "SQLMap")

def run_whatweb(target: str) -> ScanResult:
    cmd = ["whatweb", target]
    return run_tool(cmd, "WhatWeb")

def run_gitleaks(target: str) -> ScanResult:
    # Gitleaks vise usuellement un dépôt local, mais on peut faire de l'énumération .git basique
    return {"status": "info", "output": "GitLeaks (Analyse de secrets) requiert un dépôt clone local ou un scan d'URL spécifique (non applicable directement)."}

def run_lighthouse(target: str) -> ScanResult:
    url = f"http://{target}" if not target.startswith("http") else target
    # Lighthouse CLI doit être installé via npm
    cmd = ["lighthouse", url, "--output=json", "--chrome-flags=--headless", "--quiet"]
    res = run_tool(cmd, "Lighthouse")
    if res["status"] == "success":
        try:
            # Traiter un peu le JSON géant de Lighthouse
            lh_data = json.loads(res["output"])
            categories = lh_data.get("categories", {})
            scores = {k: int(v.get("score", 0) * 100) for k, v in categories.items()}
            return {"status": "success", "scores": scores}
        except Exception:
            return {"status": "error", "error": "Impossible de parser les résultats Lighthouse."}
    return res

def run_pymeta(target: str) -> ScanResult:
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    cmd = ["pymeta", "-d", domain]
    return run_tool(cmd, "PyMeta")

def run_whois(target: str) -> ScanResult:
    domain = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    cmd = ["whois", domain]
    return run_tool(cmd, "Whois")


def run_advanced_scan(target: str) -> Dict[str, ScanResult]:
    """Lance les outils d'OSINT/Scan en parallèle."""
    results: Dict[str, ScanResult] = {
        "sqlmap": {"status": "pending"},
        "whatweb": {"status": "pending"},
        "lighthouse": {"status": "pending"},
        "pymeta": {"status": "pending"},
        "gitleaks": {"status": "pending"}
    }

    # Utilisation du threading pour exécuter le tout en parallèle
    with ThreadPoolExecutor(max_workers=5) as executor:
        f_sqlmap    = executor.submit(run_sqlmap, target)     # type: ignore[arg-type]
        f_whatweb   = executor.submit(run_whatweb, target)    # type: ignore[arg-type]
        f_lighthouse= executor.submit(run_lighthouse, target) # type: ignore[arg-type]
        f_pymeta    = executor.submit(run_pymeta, target)     # type: ignore[arg-type]
        f_gitleaks  = executor.submit(run_gitleaks, target)   # type: ignore[arg-type]

        results["sqlmap"]     = f_sqlmap.result()
        results["whatweb"]    = f_whatweb.result()
        results["lighthouse"] = f_lighthouse.result()
        results["pymeta"]     = f_pymeta.result()
        results["gitleaks"]   = f_gitleaks.result()

    return results
