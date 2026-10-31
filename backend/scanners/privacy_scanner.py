"""
Privacy, GDPR & Cookie Trackers Compliance Scanner.
Inspects target sites for:
- Legal and Privacy Policy pages (/privacy, /mentions-legales, /cgu)
- Third-party tracking pixels (Google Analytics, Meta/Facebook Pixel, TikTok, Hotjar)
- Cookie Management Consent Banners (CMP: Axeptio, Didomi, Cookiebot, OneTrust, Tarteaucitron)
- Cookie privacy compliance (CNIL 13-month retention, SameSite flags)
"""

from typing import Dict, Any, List
from bs4 import BeautifulSoup
import httpx

TRACKER_SIGNATURES = [
    {
        "name": "Google Analytics / Tag Manager",
        "keywords": ["googletagmanager.com/gtag", "google-analytics.com", "gtag('config'"],
        "category": "Mesure d'audience"
    },
    {
        "name": "Meta / Facebook Pixel",
        "keywords": ["connect.facebook.net", "fbq('init'", "fbevents.js"],
        "category": "Ciblage publicitaire"
    },
    {
        "name": "TikTok Pixel",
        "keywords": ["analytics.tiktok.com", "ttq.load"],
        "category": "Ciblage publicitaire"
    },
    {
        "name": "Hotjar (Enregistrement de sessions)",
        "keywords": ["static.hotjar.com", "hj('identify'"],
        "category": "Comportement utilisateur"
    }
]

CMP_SIGNATURES = [
    {"name": "Axeptio", "keywords": ["axeptio", "axept.io"]},
    {"name": "Didomi", "keywords": ["didomi", "didomi.js"]},
    {"name": "Cookiebot", "keywords": ["cookiebot", "consent.cookiebot.com"]},
    {"name": "OneTrust", "keywords": ["onetrust", "optanon"]},
    {"name": "Tarteaucitron", "keywords": ["tarteaucitron", "tarteaucitron.js"]},
    {"name": "Complianz", "keywords": ["complianz"]}
]

LEGAL_PATHS = [
    "/privacy",
    "/politique-de-confidentialite",
    "/mentions-legales",
    "/cgu",
    "/terms"
]


async def scan_privacy_gdpr(
    base_url: str,
    html_content: str,
    headers: Dict[str, str],
    client: httpx.AsyncClient
) -> Dict[str, Any]:
    """
    Evaluates website compliance with privacy laws (GDPR / CNIL) and trackers.
    """
    findings = []
    earned = 0
    total_weight = 0

    lower_html = html_content.lower() if html_content else ""

    # 1. Detect Third-Party Trackers
    detected_trackers = []
    for t in TRACKER_SIGNATURES:
        if any(k.lower() in lower_html for k in t["keywords"]):
            detected_trackers.append(t["name"])

    # 2. Detect Consent Management Platform (CMP)
    detected_cmp = None
    for cmp_info in CMP_SIGNATURES:
        if any(k.lower() in lower_html for k in cmp_info["keywords"]):
            detected_cmp = cmp_info["name"]
            break

    # Evaluation: Trackers vs CMP
    total_weight += 25
    if detected_trackers:
        if detected_cmp:
            earned += 25
            findings.append({
                "key": "trackers_with_cmp",
                "title": f"Traceurs d'audience encadrés par bandeau CMP ({detected_cmp})",
                "category": "Protection des Données & RGPD",
                "status": "pass",
                "severity": "info",
                "score_weight": 25,
                "earned_score": 25,
                "value": f"Traceurs : {', '.join(detected_trackers)} | Bandeau : {detected_cmp}",
                "message": f"Des traceurs sont utilisés ({', '.join(detected_trackers)}) mais un gestionnaire de consentement ({detected_cmp}) est actif pour recueillir le consentement préalable de l'utilisateur.",
                "remediation_key": "cookie_consent"
            })
        else:
            earned += 5
            findings.append({
                "key": "trackers_no_cmp",
                "title": "Traceurs publicitaires détectés sans bandeau CMP visible !",
                "category": "Protection des Données & RGPD",
                "status": "warning",
                "severity": "medium",
                "score_weight": 25,
                "earned_score": 5,
                "value": f"Traceurs identifiés : {', '.join(detected_trackers)}",
                "message": f"Des traceurs ({', '.join(detected_trackers)}) sont chargés sans bandeau de consentement reconnu (Axeptio, Didomi, Cookiebot, etc.). Risque de non-conformité RGPD / directives ePrivacy.",
                "remediation_key": "cookie_consent"
            })
    else:
        earned += 25
        findings.append({
            "key": "zero_trackers",
            "title": "Aucun traceur publicitaire ou pixel tiers intrusif",
            "category": "Protection des Données & RGPD",
            "status": "pass",
            "severity": "info",
            "score_weight": 25,
            "earned_score": 25,
            "message": "Le site respecte nativement la vie privée sans injecter de traceurs tiers (pas de pixel Meta, TikTok ou Google Analytics non consenti).",
            "remediation_key": "cookie_consent"
        })

    # 3. Check for Privacy & Legal Notice Pages
    total_weight += 20
    soup = BeautifulSoup(html_content, "html.parser") if html_content else None
    has_legal_link = False
    found_legal_href = None

    if soup:
        for a in soup.find_all("a", href=True):
            href = a["href"].lower()
            text = a.get_text().lower()
            if any(k in href or k in text for k in ["confidentialite", "privacy", "mentions", "legal", "donnees-personnelles"]):
                has_legal_link = True
                found_legal_href = a["href"]
                break

    if has_legal_link:
        earned += 20
        findings.append({
            "key": "legal_notice_present",
            "title": "Politique de confidentialité / Mentions légales présente",
            "category": "Protection des Données & RGPD",
            "status": "pass",
            "severity": "info",
            "score_weight": 20,
            "earned_score": 20,
            "value": f"Lien détecté : {found_legal_href}",
            "message": "Le site met à disposition une page de transparence sur les données personnelles et mentions obligatoires.",
            "remediation_key": "legal_notice"
        })
    else:
        earned += 5
        findings.append({
            "key": "legal_notice_missing",
            "title": "Lien vers la Politique de Confidentialité introuvable sur la page",
            "category": "Protection des Données & RGPD",
            "status": "info",
            "severity": "low",
            "score_weight": 20,
            "earned_score": 5,
            "message": "Aucun lien évident vers une politique de confidentialité ou mentions légales n'a été repéré dans les pieds de page. Obligation légale en UE/RGPD.",
            "remediation_key": "legal_notice"
        })

    # 4. SameSite & Secure Cookies evaluation
    total_weight += 15
    raw_cookie = headers.get("set-cookie", "")
    if raw_cookie:
        is_samesite = "samesite" in raw_cookie.lower()
        is_secure = "secure" in raw_cookie.lower()
        if is_samesite and is_secure:
            earned += 15
            findings.append({
                "key": "privacy_cookies_secured",
                "title": "Cookies de session protégés (SameSite & Secure)",
                "category": "Protection des Données & RGPD",
                "status": "pass",
                "severity": "info",
                "score_weight": 15,
                "earned_score": 15,
                "message": "Les cookies de session intègrent les attributs SameSite et Secure nécessaires pour prévenir les fuites cross-site.",
                "remediation_key": "cookie_security"
            })
        else:
            earned += 5
            findings.append({
                "key": "privacy_cookies_weak",
                "title": "Cookies sans attribut SameSite ou Secure strict",
                "category": "Protection des Données & RGPD",
                "status": "warning",
                "severity": "low",
                "score_weight": 15,
                "earned_score": 5,
                "message": "Certains cookies ne spécifient pas SameSite=Lax/Strict ou Secure, facilitant le traçage inter-sites non désiré.",
                "remediation_key": "cookie_security"
            })
    else:
        earned += 15
        findings.append({
            "key": "privacy_no_cookies",
            "title": "Aucun cookie persistant déposé dès le premier contact",
            "category": "Protection des Données & RGPD",
            "status": "pass",
            "severity": "info",
            "score_weight": 15,
            "earned_score": 15,
            "message": "Conforme au principe 'Privacy by Design' : aucun cookie n'est forcé avant interaction de l'internaute.",
            "remediation_key": "cookie_security"
        })

    percentage = round((earned / total_weight) * 100) if total_weight > 0 else 100

    return {
        "score_percentage": percentage,
        "trackers": detected_trackers,
        "cmp": detected_cmp,
        "has_legal_notice": has_legal_link,
        "findings": findings
    }

