"""
HTTP Security Headers Scanner.
Evaluates the presence, configuration, and strength of HTTP security headers.
"""

from typing import Dict, Any, List

RECOMMENDED_HEADERS = {
    "Strict-Transport-Security": {
        "title": "HSTS (Strict-Transport-Security)",
        "category": "headers",
        "cwe": "CWE-319",
        "owasp": "A02:2021-Cryptographic Failures",
        "description": "Force le navigateur à utiliser exclusivement des connexions HTTPS chiffrées.",
        "remediation_key": "hsts"
    },
    "Content-Security-Policy": {
        "title": "CSP (Content-Security-Policy)",
        "category": "headers",
        "cwe": "CWE-79",
        "owasp": "A03:2021-Injection",
        "description": "Restreint les sources de scripts, styles et médias pour bloquer les attaques XSS et le vol de données.",
        "remediation_key": "csp"
    },
    "X-Frame-Options": {
        "title": "X-Frame-Options",
        "category": "headers",
        "cwe": "CWE-1021",
        "owasp": "A04:2021-Insecure Design",
        "description": "Empêche l'intégration du site dans des iframes invisibles afin de contrer le Clickjacking.",
        "remediation_key": "x_frame_options"
    },
    "X-Content-Type-Options": {
        "title": "X-Content-Type-Options",
        "category": "headers",
        "cwe": "CWE-430",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "Interdit au navigateur de deviner le type MIME d'un fichier (MIME-sniffing).",
        "remediation_key": "x_content_type_options"
    },
    "Referrer-Policy": {
        "title": "Referrer-Policy",
        "category": "headers",
        "cwe": "CWE-200",
        "owasp": "A01:2021-Broken Access Control",
        "description": "Contrôle les données d'URL transmises dans l'en-tête Referer lors de la navigation.",
        "remediation_key": "referrer_policy"
    },
    "Permissions-Policy": {
        "title": "Permissions-Policy",
        "category": "headers",
        "cwe": "CWE-250",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "Désactive l'accès aux API sensibles du navigateur (micro, caméra, géolocalisation).",
        "remediation_key": "permissions_policy"
    },
    "Cross-Origin-Opener-Policy": {
        "title": "COOP (Cross-Origin-Opener-Policy)",
        "category": "headers",
        "cwe": "CWE-668",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "Isole le contexte de navigation contre les fuites inter-origines (Spectre / XS-Leaks).",
        "remediation_key": "coop"
    },
    "Cross-Origin-Resource-Policy": {
        "title": "CORP (Cross-Origin-Resource-Policy)",
        "category": "headers",
        "cwe": "CWE-668",
        "owasp": "A05:2021-Security Misconfiguration",
        "description": "Empêche d'autres sites web de charger vos ressources protégées sans autorisation.",
        "remediation_key": "corp"
    }
}


def scan_security_headers(headers: Dict[str, str], is_https: bool = True) -> Dict[str, Any]:
    """
    Analyzes HTTP response headers and returns findings and score.
    """
    # Normalize headers to lowercase for easy lookup
    normalized = {k.lower(): v for k, v in headers.items()}
    
    findings: List[Dict[str, Any]] = []
    total_checks = len(RECOMMENDED_HEADERS)
    passed_checks = 0

    # 1. Check HSTS
    hsts_val = normalized.get("strict-transport-security")
    if not is_https:
        findings.append({
            "key": "Strict-Transport-Security",
            "title": "HSTS non applicable en HTTP",
            "status": "warning",
            "severity": "high",
            "score_weight": 15,
            "earned_score": 0,
            "value": None,
            "message": "Le site est accessible en HTTP non chiffré. L'en-tête HSTS n'est pris en compte qu'en HTTPS.",
            "remediation_key": "hsts"
        })
    elif not hsts_val:
        findings.append({
            "key": "Strict-Transport-Security",
            "title": "En-tête HSTS manquant",
            "status": "fail",
            "severity": "high",
            "score_weight": 15,
            "earned_score": 0,
            "value": None,
            "message": "Strict-Transport-Security n'est pas configuré. Risque d'attaque de dégradation de protocole (SSL Striping).",
            "remediation_key": "hsts"
        })
    else:
        # Check max-age
        subdomains = "includesubdomains" in hsts_val.lower()
        preload = "preload" in hsts_val.lower()
        
        # Extract max-age
        max_age = 0
        for part in hsts_val.split(";"):
            part = part.strip()
            if part.lower().startswith("max-age="):
                try:
                    max_age = int(part.split("=")[1])
                except (ValueError, IndexError):
                    pass
        
        if max_age >= 31536000:
            passed_checks += 1
            findings.append({
                "key": "Strict-Transport-Security",
                "title": "HSTS robuste",
                "status": "pass",
                "severity": "info",
                "score_weight": 15,
                "earned_score": 15,
                "value": hsts_val,
                "message": f"HSTS est actif avec une durée recommandée ({max_age}s)." + (" Avec includeSubDomains." if subdomains else "") + (" Avec preload." if preload else ""),
                "remediation_key": "hsts"
            })
        else:
            findings.append({
                "key": "Strict-Transport-Security",
                "title": "HSTS trop court",
                "status": "warning",
                "severity": "medium",
                "score_weight": 15,
                "earned_score": 7,
                "value": hsts_val,
                "message": f"La directive max-age ({max_age}s) est inférieure à 1 an (31536000s recommandé).",
                "remediation_key": "hsts"
            })

    # 2. Check CSP
    csp_val = normalized.get("content-security-policy")
    if not csp_val:
        findings.append({
            "key": "Content-Security-Policy",
            "title": "Politique CSP absente",
            "status": "fail",
            "severity": "high",
            "score_weight": 15,
            "earned_score": 0,
            "value": None,
            "message": "Aucune politique Content-Security-Policy n'est définie. Votre application est vulnérable à l'injection de scripts malveillants (XSS).",
            "remediation_key": "csp"
        })
    else:
        has_unsafe_inline = "'unsafe-inline'" in csp_val.lower()
        has_unsafe_eval = "'unsafe-eval'" in csp_val.lower()
        
        if has_unsafe_inline or has_unsafe_eval:
            findings.append({
                "key": "Content-Security-Policy",
                "title": "CSP permissive détectée",
                "status": "warning",
                "severity": "medium",
                "score_weight": 15,
                "earned_score": 8,
                "value": csp_val,
                "message": f"CSP est présente mais autorise {'unsafe-inline' if has_unsafe_inline else ''} {'unsafe-eval' if has_unsafe_eval else ''}, ce qui affaiblit la protection contre les failles XSS.",
                "remediation_key": "csp"
            })
        else:
            passed_checks += 1
            findings.append({
                "key": "Content-Security-Policy",
                "title": "CSP configurée",
                "status": "pass",
                "severity": "info",
                "score_weight": 15,
                "earned_score": 15,
                "value": csp_val,
                "message": "Une politique CSP stricte est en place pour filtrer l'exécution des ressources.",
                "remediation_key": "csp"
            })

    # 3. Check X-Frame-Options
    xfo_val = normalized.get("x-frame-options")
    if not xfo_val:
        # Check if CSP frame-ancestors is present as modern alternative
        if csp_val and "frame-ancestors" in csp_val.lower():
            passed_checks += 1
            findings.append({
                "key": "X-Frame-Options",
                "title": "Protection Clickjacking (via CSP)",
                "status": "pass",
                "severity": "info",
                "score_weight": 10,
                "earned_score": 10,
                "value": "frame-ancestors dans CSP",
                "message": "La protection contre le Clickjacking est assurée par la directive frame-ancestors de la CSP.",
                "remediation_key": "x_frame_options"
            })
        else:
            findings.append({
                "key": "X-Frame-Options",
                "title": "En-tête X-Frame-Options manquant",
                "status": "fail",
                "severity": "high",
                "score_weight": 10,
                "earned_score": 0,
                "value": None,
                "message": "Le site peut être imbriqué dans des balises <iframe> tierces. Risque d'attaque de type Clickjacking.",
                "remediation_key": "x_frame_options"
            })
    else:
        xfo_upper = xfo_val.upper().strip()
        if xfo_upper in ["DENY", "SAMEORIGIN"]:
            passed_checks += 1
            findings.append({
                "key": "X-Frame-Options",
                "title": f"X-Frame-Options ({xfo_upper})",
                "status": "pass",
                "severity": "info",
                "score_weight": 10,
                "earned_score": 10,
                "value": xfo_val,
                "message": f"Protection Clickjacking active ({xfo_upper}).",
                "remediation_key": "x_frame_options"
            })
        else:
            findings.append({
                "key": "X-Frame-Options",
                "title": "Valeur X-Frame-Options obsolète ou non standard",
                "status": "warning",
                "severity": "low",
                "score_weight": 10,
                "earned_score": 5,
                "value": xfo_val,
                "message": f"La valeur '{xfo_val}' n'est pas recommandée. Utilisez 'DENY' ou 'SAMEORIGIN'.",
                "remediation_key": "x_frame_options"
            })

    # 4. Check X-Content-Type-Options
    xcto_val = normalized.get("x-content-type-options")
    if not xcto_val:
        findings.append({
            "key": "X-Content-Type-Options",
            "title": "X-Content-Type-Options manquant",
            "status": "fail",
            "severity": "medium",
            "score_weight": 10,
            "earned_score": 0,
            "value": None,
            "message": "L'en-tête n'est pas configuré. Le navigateur pourrait interpréter des fichiers texte/images comme du code exécutable (MIME Sniffing).",
            "remediation_key": "x_content_type_options"
        })
    elif "nosniff" in xcto_val.lower():
        passed_checks += 1
        findings.append({
            "key": "X-Content-Type-Options",
            "title": "X-Content-Type-Options actif (nosniff)",
            "status": "pass",
            "severity": "info",
            "score_weight": 10,
            "earned_score": 10,
            "value": xcto_val,
            "message": "Le navigateur respectera strictement les en-têtes Content-Type déclarés.",
            "remediation_key": "x_content_type_options"
        })
    else:
        findings.append({
            "key": "X-Content-Type-Options",
            "title": "Valeur invalide pour X-Content-Type-Options",
            "status": "warning",
            "severity": "low",
            "score_weight": 10,
            "earned_score": 3,
            "value": xcto_val,
            "message": "La valeur doit être impérativement 'nosniff'.",
            "remediation_key": "x_content_type_options"
        })

    # 5. Check Referrer-Policy
    ref_val = normalized.get("referrer-policy")
    if not ref_val:
        findings.append({
            "key": "Referrer-Policy",
            "title": "Referrer-Policy manquant",
            "status": "warning",
            "severity": "low",
            "score_weight": 10,
            "earned_score": 0,
            "value": None,
            "message": "Aucune politique Referrer-Policy explicite. Les URL complètes de vos pages pourraient fuiter vers des services tiers.",
            "remediation_key": "referrer_policy"
        })
    else:
        secure_policies = ["no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"]
        if any(p in ref_val.lower() for p in secure_policies):
            passed_checks += 1
            findings.append({
                "key": "Referrer-Policy",
                "title": f"Referrer-Policy sécurisée ({ref_val})",
                "status": "pass",
                "severity": "info",
                "score_weight": 10,
                "earned_score": 10,
                "value": ref_val,
                "message": "La politique de transmission du Referer protège la confidentialité des URL internes.",
                "remediation_key": "referrer_policy"
            })
        else:
            findings.append({
                "key": "Referrer-Policy",
                "title": f"Referrer-Policy permissive ({ref_val})",
                "status": "warning",
                "severity": "low",
                "score_weight": 10,
                "earned_score": 4,
                "value": ref_val,
                "message": "Politique permissive. Il est recommandé d'utiliser 'strict-origin-when-cross-origin'.",
                "remediation_key": "referrer_policy"
            })

    # 6. Check Permissions-Policy
    perm_val = normalized.get("permissions-policy") or normalized.get("feature-policy")
    if not perm_val:
        findings.append({
            "key": "Permissions-Policy",
            "title": "Permissions-Policy absente",
            "status": "warning",
            "severity": "low",
            "score_weight": 5,
            "earned_score": 0,
            "value": None,
            "message": "Permissions-Policy non définie. Il est conseillé de désactiver les API non utilisées (caméra, géolocalisation, etc.).",
            "remediation_key": "permissions_policy"
        })
    else:
        passed_checks += 1
        findings.append({
            "key": "Permissions-Policy",
            "title": "Permissions-Policy configurée",
            "status": "pass",
            "severity": "info",
            "score_weight": 5,
            "earned_score": 5,
            "value": perm_val,
            "message": "Les fonctionnalités du navigateur sont restreintes selon les besoins déclarés.",
            "remediation_key": "permissions_policy"
        })

    # 7. Check Cross-Origin-Opener-Policy (COOP)
    coop_val = normalized.get("cross-origin-opener-policy")
    if coop_val:
        passed_checks += 1
        findings.append({
            "key": "Cross-Origin-Opener-Policy",
            "title": f"COOP actif ({coop_val})",
            "status": "pass",
            "severity": "info",
            "score_weight": 5,
            "earned_score": 5,
            "value": coop_val,
            "message": "Isolation du contexte de navigation activée.",
            "remediation_key": "coop"
        })
    else:
        findings.append({
            "key": "Cross-Origin-Opener-Policy",
            "title": "COOP non configuré",
            "status": "info",
            "severity": "low",
            "score_weight": 5,
            "earned_score": 2,
            "value": None,
            "message": "Recommandé pour les applications traitant des données hautement sensibles.",
            "remediation_key": "coop"
        })

    # 8. Check Cross-Origin-Resource-Policy (CORP)
    corp_val = normalized.get("cross-origin-resource-policy")
    if corp_val:
        passed_checks += 1
        findings.append({
            "key": "Cross-Origin-Resource-Policy",
            "title": f"CORP actif ({corp_val})",
            "status": "pass",
            "severity": "info",
            "score_weight": 5,
            "earned_score": 5,
            "value": corp_val,
            "message": "Protection contre le chargement non autorisé des ressources activée.",
            "remediation_key": "corp"
        })
    else:
        findings.append({
            "key": "Cross-Origin-Resource-Policy",
            "title": "CORP non configuré",
            "status": "info",
            "severity": "low",
            "score_weight": 5,
            "earned_score": 2,
            "value": None,
            "message": "Empêche l'inclusion de vos ressources statiques sur des sites tiers.",
            "remediation_key": "corp"
        })

    # Cookies security check
    set_cookie_raw = headers.get("set-cookie") or headers.get("Set-Cookie")
    cookies_analysis = []
    if set_cookie_raw:
        # Multiple Set-Cookie headers may be combined or single
        cookies = [c.strip() for c in set_cookie_raw.split("\n")]
        for cookie in cookies:
            cookie_lower = cookie.lower()
            name = cookie.split("=")[0].strip()
            has_secure = "secure" in cookie_lower
            has_httponly = "httponly" in cookie_lower
            has_samesite = "samesite" in cookie_lower

            issues = []
            if not has_secure and is_https:
                issues.append("Flag 'Secure' manquant (le cookie peut transiter en clair)")
            if not has_httponly:
                issues.append("Flag 'HttpOnly' manquant (accessible en JavaScript / risque XSS)")
            if not has_samesite:
                issues.append("Flag 'SameSite' manquant (risque CSRF)")

            cookies_analysis.append({
                "cookie_name": name,
                "secure": has_secure,
                "httponly": has_httponly,
                "samesite": has_samesite,
                "issues": issues,
                "status": "pass" if not issues else "warning"
            })

    total_earned = sum(f["earned_score"] for f in findings)
    max_possible = sum(f["score_weight"] for f in findings)
    percentage = round((total_earned / max_possible) * 100) if max_possible > 0 else 0

    return {
        "score_percentage": percentage,
        "total_checks": total_checks,
        "passed_checks": passed_checks,
        "findings": findings,
        "cookies": cookies_analysis,
        "raw_headers": {k: v for k, v in headers.items()}
    }

