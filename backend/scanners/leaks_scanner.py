"""
Information Disclosure & Server Leaks Scanner.
Detects server banner disclosures, exposed debug headers, and publicly accessible sensitive assets.
"""

from typing import Dict, Any, List
import httpx


async def scan_information_leaks(base_url: str, headers: Dict[str, str], client: httpx.AsyncClient) -> Dict[str, Any]:
    """
    Passively analyzes response headers and performs safe passive checks for exposure.
    """
    findings: List[Dict[str, Any]] = []
    normalized = {k.lower(): v for k, v in headers.items()}

    # 1. Server Header Disclosure
    server_header = normalized.get("server")
    if not server_header:
        findings.append({
            "key": "server_header_hidden",
            "title": "Bannière Serveur masquée",
            "status": "pass",
            "severity": "info",
            "score_weight": 10,
            "earned_score": 10,
            "message": "Aucun en-tête 'Server' détaillé n'est divulgué publiquement.",
            "remediation_key": "server_tokens"
        })
    else:
        # Check if version number is present (e.g., Apache/2.4.51, nginx/1.18.0)
        has_version = any(char.isdigit() for char in server_header)
        if has_version:
            findings.append({
                "key": "server_version_exposed",
                "title": f"Version précise du serveur exposée ({server_header})",
                "status": "warning",
                "severity": "medium",
                "score_weight": 10,
                "earned_score": 0,
                "value": server_header,
                "message": f"Le serveur dévoile sa version exacte : '{server_header}'. Facilite la recherche de failles CVE connues par des attaquants.",
                "remediation_key": "server_tokens"
            })
        else:
            findings.append({
                "key": "server_header_generic",
                "title": f"Bannière Serveur générique ({server_header})",
                "status": "pass",
                "severity": "info",
                "score_weight": 10,
                "earned_score": 8,
                "value": server_header,
                "message": f"Bannière générique détectée sans numéro de version précis ({server_header}).",
                "remediation_key": "server_tokens"
            })

    # 2. X-Powered-By Header
    powered_by = normalized.get("x-powered-by")
    if powered_by:
        findings.append({
            "key": "x_powered_by_exposed",
            "title": f"En-tête X-Powered-By divulgué ({powered_by})",
            "status": "fail",
            "severity": "medium",
            "score_weight": 10,
            "earned_score": 0,
            "value": powered_by,
            "message": f"La technologie du backend ({powered_by}) est publiquement affichée. Supprimez cet en-tête.",
            "remediation_key": "x_powered_by"
        })
    else:
        findings.append({
            "key": "x_powered_by_hidden",
            "title": "Technologie Backend masquée",
            "status": "pass",
            "severity": "info",
            "score_weight": 10,
            "earned_score": 10,
            "message": "En-tête X-Powered-By absent, aucune empreinte technologique superflue.",
            "remediation_key": "x_powered_by"
        })

    # 3. Security.txt (RFC 9116)
    security_txt_url = f"{base_url.rstrip('/')}/.well-known/security.txt"
    has_security_txt = False
    try:
        sec_resp = await client.get(security_txt_url, timeout=4.0)
        if sec_resp.status_code == 200 and "contact" in sec_resp.text.lower():
            has_security_txt = True
            findings.append({
                "key": "security_txt_present",
                "title": "Fichier security.txt (RFC 9116) présent",
                "status": "pass",
                "severity": "info",
                "score_weight": 5,
                "earned_score": 5,
                "message": "Le site propose une politique de divulgation responsable des vulnérabilités.",
                "remediation_key": "security_txt"
            })
    except Exception:
        pass

    if not has_security_txt:
        findings.append({
            "key": "security_txt_missing",
            "title": "Fichier security.txt absent",
            "status": "info",
            "severity": "low",
            "score_weight": 5,
            "earned_score": 2,
            "message": "L'absence de /.well-known/security.txt complique le signalement éthique de failles par les chercheurs en sécurité.",
            "remediation_key": "security_txt"
        })

    # 4. Passive check for publicly exposed sensitive files (Git / Env)
    sensitive_tests = [
        {"path": "/.env", "signature": "DB_", "title": "Fichier d'environnement .env exposé !"},
        {"path": "/.git/HEAD", "signature": "ref: refs/", "title": "Dépôt Git source /.git/HEAD exposé !"}
    ]
    
    for item in sensitive_tests:
        test_url = f"{base_url.rstrip('/')}{item['path']}"
        try:
            resp = await client.get(test_url, timeout=3.5)
            if resp.status_code == 200 and item["signature"] in resp.text:
                findings.append({
                    "key": f"leak_{item['path']}",
                    "title": item["title"],
                    "status": "fail",
                    "severity": "critical",
                    "score_weight": 20,
                    "earned_score": 0,
                    "message": f"ALERTE SÉCURITÉ CRITIQUE : Le fichier sensible {item['path']} est accessible publiquement et contient des données confidentielles !",
                    "remediation_key": "block_sensitive_paths"
                })
        except Exception:
            pass

    total_earned = sum(f["earned_score"] for f in findings)
    max_possible = sum(f["score_weight"] for f in findings)
    percentage = round((total_earned / max_possible) * 100) if max_possible > 0 else 0

    return {
        "score_percentage": percentage,
        "server_header": server_header,
        "powered_by": powered_by,
        "has_security_txt": has_security_txt,
        "findings": findings
    }

