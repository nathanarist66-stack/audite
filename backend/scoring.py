"""
Security Scoring and Evaluation Engine.
Computes a weighted global security score (0-100), letter grade (A+ to F),
and enriches all findings with remediation recommendations.
"""

from typing import Dict, Any, List, Optional
from .remediations import get_remediation


def calculate_grade(score: int) -> Dict[str, str]:
    """Returns grade letter and color code based on score."""
    if score >= 95:
        return {"grade": "A+", "label": "Excellent", "color": "emerald"}
    elif score >= 85:
        return {"grade": "A", "label": "Très bon", "color": "emerald"}
    elif score >= 75:
        return {"grade": "B", "label": "Bon", "color": "cyan"}
    elif score >= 60:
        return {"grade": "C", "label": "Moyen", "color": "amber"}
    elif score >= 40:
        return {"grade": "D", "label": "Vulnérable", "color": "orange"}
    else:
        return {"grade": "F", "label": "Critique", "color": "red"}


def compile_audit_report(
    target_url: str,
    headers_res: Dict[str, Any],
    ssl_res: Dict[str, Any],
    dns_res: Dict[str, Any],
    leaks_res: Dict[str, Any],
    html_res: Optional[Dict[str, Any]] = None,
    secrets_res: Optional[Dict[str, Any]] = None,
    privacy_res: Optional[Dict[str, Any]] = None,
    reputation_res: Optional[Dict[str, Any]] = None,
    sitemap_res: Optional[Dict[str, Any]] = None,
    cms_res: Optional[Dict[str, Any]] = None,
    subdomains_res: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Combines all scanner results into a comprehensive audit report with remediations.
    """
    if html_res is None:
        html_res = {"score_percentage": 100, "findings": []}
    if secrets_res is None:
        secrets_res = {"score_percentage": 100, "findings": [], "detected_count": 0}
    if privacy_res is None:
        privacy_res = {"score_percentage": 100, "findings": [], "trackers": []}
    if reputation_res is None:
        reputation_res = {"score_percentage": 100, "findings": [], "listed_on": []}
    if sitemap_res is None:
        sitemap_res = {"findings": []}
    if cms_res is None:
        cms_res = {"cms_name": "Inconnu", "findings": []}
    if subdomains_res is None:
        subdomains_res = {"subdomains": [], "findings": []}

    # Weighted score calculation across all security dimensions:
    # Headers: 25%, SSL: 25%, DNS: 15%, HTML & Secrets: 15%, Leaks: 10%, Privacy & RGPD: 10%
    h_score = headers_res.get("score_percentage", 0)
    s_score = ssl_res.get("score_percentage", 0)
    d_score = dns_res.get("score_percentage", 0)
    
    # Combined HTML & Secrets score
    raw_html_score = html_res.get("score_percentage", 100)
    sec_score = secrets_res.get("score_percentage", 100)
    html_combined_score = round((raw_html_score * 0.5) + (sec_score * 0.5))

    l_score = leaks_res.get("score_percentage", 0)
    priv_score = privacy_res.get("score_percentage", 100)

    # Severe penalty if an exposed secret (Stripe, AWS, GitHub) is detected
    penalty = 0
    if secrets_res.get("detected_count", 0) > 0:
        penalty += (secrets_res["detected_count"] * 20)

    # Severe penalty if IP is blacklisted on spam/malware databases
    if reputation_res.get("listed_on"):
        penalty += 15

    base_score = round(
        (h_score * 0.25) +
        (s_score * 0.25) +
        (d_score * 0.15) +
        (html_combined_score * 0.15) +
        (l_score * 0.10) +
        (priv_score * 0.10)
    )

    global_score = max(0, min(100, base_score - penalty))
    grade_info = calculate_grade(global_score)

    # Collect all findings and attach remediations
    all_findings: List[Dict[str, Any]] = []
    
    categories = [
        ("Headers HTTP", headers_res),
        ("Chiffrement SSL/TLS", ssl_res),
        ("DNS & Anti-Spoofing", dns_res),
        ("Réputation IP & Blacklists", reputation_res),
        ("Sécurité HTML & Scripts", html_res),
        ("Fuites de Clés & Secrets", secrets_res),
        ("Exposition & Fuites", leaks_res),
        ("Protection des Données & RGPD", privacy_res),
        ("Exploration Multi-Pages & Sitemap", sitemap_res),
        ("Exposition & CMS", cms_res),
        ("Cartographie & Sous-domaines", subdomains_res)
    ]

    for category_name, res in categories:
        for finding in res.get("findings", []):
            item = dict(finding)
            item["category"] = item.get("category") or category_name
            # Attach remediation if present
            remed_key = item.get("remediation_key")
            if remed_key:
                item["remediation"] = get_remediation(remed_key)
            all_findings.append(item)

    # Sort findings by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 5))

    critical_count = sum(1 for f in all_findings if f.get("severity") == "critical" and f.get("status") in ["fail", "warning"])
    high_count = sum(1 for f in all_findings if f.get("severity") == "high" and f.get("status") in ["fail", "warning"])
    medium_count = sum(1 for f in all_findings if f.get("severity") == "medium" and f.get("status") in ["fail", "warning"])
    low_count = sum(1 for f in all_findings if f.get("severity") == "low" and f.get("status") in ["fail", "warning"])
    passed_count = sum(1 for f in all_findings if f.get("status") == "pass")

    return {
        "url": target_url,
        "global_score": global_score,
        "grade": grade_info["grade"],
        "grade_label": grade_info["label"],
        "grade_color": grade_info["color"],
        "summary": {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "passed": passed_count,
            "total_checks": len(all_findings)
        },
        "pillars": {
            "headers": {
                "title": "En-têtes HTTP de sécurité",
                "score": h_score,
                "passed": headers_res.get("passed_checks", 0),
                "total": headers_res.get("total_checks", 0)
            },
            "ssl": {
                "title": "Chiffrement SSL/TLS",
                "score": s_score,
                "protocol": ssl_res.get("protocol"),
                "issuer": ssl_res.get("issuer"),
                "expires_in_days": ssl_res.get("expires_in_days")
            },
            "dns": {
                "title": "Protection DNS & Messagerie",
                "score": d_score,
                "has_spf": bool(dns_res.get("spf_record")),
                "has_dmarc": bool(dns_res.get("dmarc_record")),
                "dnssec": dns_res.get("dnssec_active", False)
            },
            "html": {
                "title": "Sécurité HTML & Scripts",
                "score": html_combined_score,
                "detected_libraries": html_res.get("detected_libraries", []),
                "scripts_count": html_res.get("scripts_count", 0),
                "mixed_content_count": html_res.get("mixed_content_count", 0),
                "secrets_detected": secrets_res.get("detected_count", 0)
            },
            "leaks": {
                "title": "Exposition & Informations Serveur",
                "score": l_score,
                "server": leaks_res.get("server_header"),
                "has_security_txt": leaks_res.get("has_security_txt", False)
            },
            "privacy": {
                "title": "Protection des Données & RGPD",
                "score": priv_score,
                "trackers": privacy_res.get("trackers", []),
                "cmp": privacy_res.get("cmp"),
                "has_legal_notice": privacy_res.get("has_legal_notice", False)
            },
            "reputation": {
                "title": "Réputation IP & Blacklists",
                "score": reputation_res.get("score_percentage", 100),
                "ip": reputation_res.get("ip"),
                "listed_on": reputation_res.get("listed_on", [])
            }
        },
        "findings": all_findings,
        "cms": cms_res,
        "subdomains": subdomains_res,
        "raw_data": {
            "headers": headers_res.get("raw_headers", {}),
            "ssl": {k: v for k, v in ssl_res.items() if k != "findings"},
            "dns": {k: v for k, v in dns_res.items() if k != "findings"}
        }
    }

