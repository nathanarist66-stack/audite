"""
HTML & Client-Side Code Security Scanner.
Passively parses the HTML document body to detect:
- Outdated / vulnerable JavaScript libraries (jQuery, Bootstrap, AngularJS, etc.)
- Missing Subresource Integrity (SRI) on external CDNs
- Mixed content (HTTP assets on HTTPS pages)
- Insecure password / login form submissions
- Reverse Tabnabbing (target="_blank" without rel="noopener")
"""

import re
from typing import Dict, Any, List
from urllib.parse import urlparse
from bs4 import BeautifulSoup

KNOWN_VULNERABLE_LIBS = [
    {
        "name": "jQuery",
        "pattern": r"jquery[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "check": lambda v: compare_versions(v, "3.5.0") < 0,
        "cve": "CVE-2020-11022 / CVE-2020-11023",
        "severity": "high",
        "message": "Version obsolète de jQuery (< 3.5.0) vulnérable aux attaques Cross-Site Scripting (XSS) via htmlPrefilter."
    },
    {
        "name": "Bootstrap",
        "pattern": r"bootstrap[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "check": lambda v: compare_versions(v, "4.5.0") < 0,
        "cve": "CVE-2019-8331",
        "severity": "medium",
        "message": "Version ancienne de Bootstrap (< 4.5.0) contenant des vulnérabilités XSS dans les composants Tooltip et Popover."
    },
    {
        "name": "AngularJS 1.x",
        "pattern": r"angular[.-](1\.[0-9]+(?:\.[0-9]+)?)",
        "check": lambda v: True,
        "cve": "Fin de vie (EOL) / Multiples CVEs",
        "severity": "high",
        "message": "AngularJS 1.x a atteint sa fin de vie (End of Life) et n'est plus maintenu par Google. Risque de failles non corrigées."
    },
    {
        "name": "Lodash",
        "pattern": r"lodash[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "check": lambda v: compare_versions(v, "4.17.21") < 0,
        "cve": "CVE-2021-23337",
        "severity": "high",
        "message": "Version obsolète de Lodash (< 4.17.21) vulnérable à la pollution de prototype (Command Injection)."
    }
]

KNOWN_CDNS = [
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "stackpath.bootstrapcdn.com",
    "code.jquery.com",
    "ajax.googleapis.com"
]


def compare_versions(v1: str, v2: str) -> int:
    """Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2."""
    def parse(v):
        return [int(x) for x in re.sub(r'[^0-9.]', '', v).split('.') if x.isdigit()]
    p1 = parse(v1)
    p2 = parse(v2)
    # Pad to equal length
    max_len = max(len(p1), len(p2))
    p1 += [0] * (max_len - len(p1))
    p2 += [0] * (max_len - len(p2))
    if p1 < p2:
        return -1
    elif p1 > p2:
        return 1
    return 0


def scan_html_security(html_content: str, base_url: str, is_https: bool = True) -> Dict[str, Any]:
    """
    Performs passive security inspection of the HTML document.
    """
    findings: List[Dict[str, Any]] = []
    
    if not html_content or len(html_content.strip()) == 0:
        return {
            "score_percentage": 100,
            "detected_libraries": [],
            "scripts_count": 0,
            "forms_count": 0,
            "findings": []
        }

    soup = BeautifulSoup(html_content, "html.parser")
    
    # 1. Outdated JavaScript Libraries Detection
    scripts = soup.find_all("script")
    detected_libs = []
    scripts_missing_sri = []

    for s in scripts:
        src = s.get("src", "")
        if not src:
            continue

        # Check for known vulnerable versions
        for lib in KNOWN_VULNERABLE_LIBS:
            match = re.search(lib["pattern"], src, re.IGNORECASE)
            if match:
                version = match.group(1)
                if lib["check"](version):
                    item_key = f"vuln_{lib['name']}_{version}"
                    if not any(f["key"] == item_key for f in findings):
                        detected_libs.append(f"{lib['name']} {version}")
                        findings.append({
                            "key": item_key,
                            "title": f"Bibliothèque vulnérable : {lib['name']} v{version}",
                            "status": "fail",
                            "severity": lib["severity"],
                            "score_weight": 15,
                            "earned_score": 0,
                            "value": src,
                            "message": f"{lib['message']} ({lib['cve']}). Mettez à jour vers la version la plus récente.",
                            "remediation_key": "update_js_libs"
                        })

        # Check SRI on external CDNs
        parsed_src = urlparse(src)
        if parsed_src.netloc:
            is_cdn = any(cdn in parsed_src.netloc.lower() for cdn in KNOWN_CDNS)
            has_sri = bool(s.get("integrity"))
            if is_cdn and not has_sri:
                scripts_missing_sri.append(src)

    if scripts_missing_sri:
        findings.append({
            "key": "missing_sri",
            "title": "Attribut SRI manquant sur des scripts CDN",
            "status": "warning",
            "severity": "medium",
            "score_weight": 10,
            "earned_score": 4,
            "value": f"{len(scripts_missing_sri)} script(s) externe(s) sans integrity='sha384-...'",
            "message": "Des scripts externes sont hébergés sur des CDN tiers sans contrôle d'intégrité (Subresource Integrity). Si le CDN est compromis, un attaquant peut exécuter du code malveillant sur vos pages.",
            "remediation_key": "enable_sri"
        })
    else:
        findings.append({
            "key": "sri_compliant",
            "title": "Scripts externes sécurisés ou locaux",
            "status": "pass",
            "severity": "info",
            "score_weight": 10,
            "earned_score": 10,
            "message": "Tous les scripts chargés respectent les règles d'intégrité ou sont hébergés localement.",
            "remediation_key": "enable_sri"
        })

    # 2. Insecure Forms (Password over HTTP or plain action)
    forms = soup.find_all("form")
    insecure_forms = []
    has_password_field = False

    for f in forms:
        action = f.get("action", "").strip()
        pwd_input = f.find("input", {"type": "password"})
        if pwd_input:
            has_password_field = True
            if action.lower().startswith("http://") or (not is_https and not action.lower().startswith("https://")):
                insecure_forms.append(action or "(action locale)")

    if insecure_forms:
        findings.append({
            "key": "insecure_login_form",
            "title": "Formulaire d'authentification non chiffré !",
            "status": "fail",
            "severity": "critical",
            "score_weight": 20,
            "earned_score": 0,
            "value": f"Action du formulaire : {insecure_forms[0]}",
            "message": "Un formulaire de saisie de mot de passe transmet les identifiants en clair ou sur une page non sécurisée. Risque immédiat d'interception de compte.",
            "remediation_key": "secure_forms"
        })
    elif has_password_field and is_https:
        findings.append({
            "key": "secure_login_form",
            "title": "Formulaires d'authentification sécurisés",
            "status": "pass",
            "severity": "info",
            "score_weight": 15,
            "earned_score": 15,
            "message": "Les champs de saisie sensibles (mots de passe) sont protégés par le chiffrement HTTPS.",
            "remediation_key": "secure_forms"
        })

    # 3. Mixed Content Check (HTTP assets on HTTPS page)
    mixed_content_count = 0
    if is_https:
        for tag, attr in [("img", "src"), ("script", "src"), ("link", "href"), ("iframe", "src")]:
            for el in soup.find_all(tag):
                val = el.get(attr, "")
                if val.lower().startswith("http://"):
                    mixed_content_count += 1

    if mixed_content_count > 0:
        findings.append({
            "key": "mixed_content",
            "title": "Contenu Mixte détecté (Mixed Content)",
            "status": "warning",
            "severity": "medium",
            "score_weight": 10,
            "earned_score": 3,
            "value": f"{mixed_content_count} ressource(s) chargée(s) en HTTP sur une page HTTPS",
            "message": "Votre page HTTPS charge des ressources (images, styles ou scripts) en HTTP non chiffré. Les navigateurs modernes bloquent ou avertissent les internautes.",
            "remediation_key": "fix_mixed_content"
        })
    elif is_https:
        findings.append({
            "key": "no_mixed_content",
            "title": "Aucun contenu mixte détecté",
            "status": "pass",
            "severity": "info",
            "score_weight": 10,
            "earned_score": 10,
            "message": "Toutes les ressources de la page sont chargées via des liaisons chiffrées HTTPS.",
            "remediation_key": "fix_mixed_content"
        })

    # 4. Reverse Tabnabbing Check (target="_blank" without rel="noopener")
    unsafe_links = []
    links = soup.find_all("a", target="_blank")
    for a in links:
        rel = a.get("rel")
        rel_str = " ".join(rel) if isinstance(rel, list) else (rel or "")
        rel_lower = rel_str.lower()
        if "noopener" not in rel_lower and "noreferrer" not in rel_lower:
            unsafe_links.append(a.get("href", ""))

    if len(unsafe_links) > 2:
        findings.append({
            "key": "reverse_tabnabbing",
            "title": f"Vulnérabilité Reverse Tabnabbing ({len(unsafe_links)} liens)",
            "status": "warning",
            "severity": "low",
            "score_weight": 5,
            "earned_score": 2,
            "value": f"{len(unsafe_links)} lien(s) avec target='_blank' sans rel='noopener'",
            "message": "Des liens ouvrant un nouvel onglet ne possèdent pas rel='noopener'. La page cible peut manipuler window.opener pour rediriger votre utilisateur vers une page de phishing.",
            "remediation_key": "tabnabbing"
        })

    total_earned = sum(f["earned_score"] for f in findings)
    max_possible = sum(f["score_weight"] for f in findings)
    percentage = round((total_earned / max_possible) * 100) if max_possible > 0 else 100

    return {
        "score_percentage": percentage,
        "detected_libraries": detected_libs,
        "scripts_count": len(scripts),
        "forms_count": len(forms),
        "mixed_content_count": mixed_content_count,
        "findings": findings
    }

