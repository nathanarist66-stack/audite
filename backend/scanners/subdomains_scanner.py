"""
Audite Security Engine - Subdomains Passive Discovery (Certificate Transparency)
Interroge passivement les journaux SSL publics (crt.sh) pour cartographier
les sous-domaines et repérer les serveurs sensibles ou oubliés (dev, staging, admin, etc.).
"""

import re
from typing import Dict, Any, List, Set
import httpx


SENSITIVE_KEYWORDS = [
    "dev", "devel", "staging", "stage", "test", "demo", "admin", "cpanel",
    "webmail", "mail", "vpn", "corp", "internal", "intranet", "portal",
    "preprod", "uat", "api", "auth", "login", "ssh", "git", "gitlab", "jenkins"
]


async def discover_subdomains_passive(
    hostname: str,
    client: httpx.AsyncClient
) -> Dict[str, Any]:
    """
    Découvre passivement les sous-domaines via les journaux Certificate Transparency.
    """
    clean_host = hostname.lower().strip()
    # Enlever le 'www.' initial pour avoir le domaine racine
    if clean_host.startswith("www."):
        root_domain = clean_host[4:]
    else:
        root_domain = clean_host

    subdomains: Set[str] = set()
    sensitive_found: List[str] = []
    findings: List[Dict[str, Any]] = []

    # Requête passive sur crt.sh
    crt_url = f"https://crt.sh/?q=%25.{root_domain}&output=json"
    try:
        res = await client.get(crt_url, timeout=4.5)
        if res.status_code == 200:
            entries = res.json()
            if isinstance(entries, list):
                for entry in entries:
                    name_val = entry.get("name_value", "")
                    # name_value peut contenir plusieurs sous-domaines séparés par des sauts de ligne
                    for sub in name_val.split("\n"):
                        sub = sub.strip().lower()
                        # Enlever les wildcards *.
                        if sub.startswith("*."):
                            sub = sub[2:]
                        if sub.endswith(root_domain) and sub != root_domain:
                            subdomains.add(sub)
    except Exception:
        # crt.sh indisponible ou délai dépassé : échec passif gracieux
        pass

    sorted_subs = sorted(list(subdomains))

    # Analyser les sous-domaines sensibles
    for sub in sorted_subs:
        prefix = sub.replace(f".{root_domain}", "")
        parts = prefix.split(".")
        if any(kw in parts or any(kw in p for p in parts) for kw in SENSITIVE_KEYWORDS):
            if sub not in sensitive_found:
                sensitive_found.append(sub)

    if sensitive_found:
        display_sensitive = ", ".join(sensitive_found[:5])
        findings.append({
            "key": "sensitive_subdomains_exposed",
            "title": f"Surface d'attaque : {len(sensitive_found)} sous-domaine(s) sensible(s) identifié(s)",
            "category": "Cartographie & Exposition",
            "status": "info",
            "severity": "medium",
            "score_weight": 5,
            "earned_score": 2,
            "value": display_sensitive,
            "message": f"Des sous-domaines potentiellement sensibles ont été identifiés dans les registres publics SSL ({display_sensitive}). Assurez-vous que ces environnements de test/développement ne sont pas accessibles sans authentification ou restreignez-les par VPN/IP.",
            "remediation_key": "subdomains_exposure"
        })

    return {
        "root_domain": root_domain,
        "total_subdomains": len(sorted_subs),
        "subdomains": sorted_subs[:30],  # Limite à 30 pour le payload
        "sensitive_subdomains": sensitive_found,
        "findings": findings
    }
