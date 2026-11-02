"""
Audite Security Engine - CMS & WordPress Scanner Module
Détecte passivement les CMS (WordPress, Shopify, PrestaShop, Wix, etc.)
et audite les vulnérabilités courantes de configuration WordPress.
"""

import re
import json
from typing import Dict, Any, List, Optional
import httpx


async def scan_cms_security(
    base_url: str,
    html_content: str,
    headers: Dict[str, str],
    client: httpx.AsyncClient
) -> Dict[str, Any]:
    """
    Détecte le CMS du site et audite les failles d'exposition courantes (ex: WordPress).
    """
    findings: List[Dict[str, Any]] = []
    cms_name = "Sur-Mesure / Standard"
    detected_version: Optional[str] = None

    url_clean = base_url.rstrip("/")
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    html_lower = html_content.lower()

    # 1. DÉTECTION DU CMS
    is_wordpress = False
    is_shopify = False
    is_prestashop = False
    is_wix = False
    is_webflow = False

    # Signatures WordPress
    if (
        "wp-content" in html_lower
        or "wp-includes" in html_lower
        or "wordpress" in headers_lower.get("x-powered-by", "")
        or "wordpress" in headers_lower.get("generator", "")
    ):
        is_wordpress = True
        cms_name = "WordPress"

    # Signatures Shopify
    elif "cdn.shopify.com" in html_lower or "shopify.theme" in html_lower:
        is_shopify = True
        cms_name = "Shopify"

    # Signatures PrestaShop
    elif "prestashop" in html_lower or "prestathemecache" in html_lower:
        is_prestashop = True
        cms_name = "PrestaShop"

    # Signatures Wix
    elif "wix.com" in html_lower or "x-wix-renderer-server" in headers_lower:
        is_wix = True
        cms_name = "Wix"

    # Signatures Webflow
    elif "webflow" in html_lower or "assets.website-files.com" in html_lower:
        is_webflow = True
        cms_name = "Webflow"

    # Détection de version via meta generator
    gen_match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
    if gen_match:
        gen_content = gen_match.group(1)
        if "wordpress" in gen_content.lower():
            cms_name = "WordPress"
            is_wordpress = True
            ver_match = re.search(r'wordpress\s*([\d\.]+)', gen_content, re.IGNORECASE)
            if ver_match:
                detected_version = ver_match.group(1)

    # 2. AUDIT SPÉCIFIQUE WORDPRESS
    if is_wordpress:
        # Check A: Énumération d'utilisateurs via REST API (/wp-json/wp/v2/users)
        try:
            res_users = await client.get(f"{url_clean}/wp-json/wp/v2/users", timeout=4.0)
            if res_users.status_code == 200:
                try:
                    users_data = res_users.json()
                    if isinstance(users_data, list) and len(users_data) > 0:
                        usernames = [u.get("slug") or u.get("name") for u in users_data if isinstance(u, dict)]
                        usernames_str = ", ".join(filter(None, usernames[:4]))
                        findings.append({
                            "key": "wp_users_exposed",
                            "title": "Énumération d'utilisateurs WordPress active (/wp-json/wp/v2/users)",
                            "category": "Exposition & CMS",
                            "status": "fail",
                            "severity": "high",
                            "score_weight": 15,
                            "earned_score": 0,
                            "value": f"Comptes exposés : {usernames_str}",
                            "message": f"L'API REST WordPress divulgue publiquement les identifiants d'administration ({usernames_str}). Les pirates ont déjà la moitié des informations pour forcer l'accès par mot de passe.",
                            "remediation_key": "wp_disable_rest_users"
                        })
                except Exception:
                    pass
        except Exception:
            pass

        # Check B: Protocole XML-RPC (/xmlrpc.php)
        try:
            res_xmlrpc = await client.post(
                f"{url_clean}/xmlrpc.php",
                content="<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>",
                headers={"Content-Type": "text/xml"},
                timeout=4.0
            )
            # Si le serveur répond avec du XML contenant des méthodes ou status 200/405
            if res_xmlrpc.status_code == 200 and "methodResponse" in res_xmlrpc.text:
                findings.append({
                    "key": "wp_xmlrpc_enabled",
                    "title": "Protocole XML-RPC actif et non protégé (/xmlrpc.php)",
                    "category": "Exposition & CMS",
                    "status": "fail",
                    "severity": "medium",
                    "score_weight": 10,
                    "earned_score": 0,
                    "value": "XML-RPC Server actif",
                    "message": "Le fichier xmlrpc.php est exposé. Il permet des attaques de force brute amplifiées (tester des centaines de mots de passe en une seule requête) et des relais d'attaque DDoS par pingback.",
                    "remediation_key": "wp_block_xmlrpc"
                })
        except Exception:
            pass

        # Check C: Page de connexion standard (/wp-login.php)
        try:
            res_login = await client.get(f"{url_clean}/wp-login.php", timeout=4.0)
            if res_login.status_code == 200 and "user_login" in res_login.text:
                findings.append({
                    "key": "wp_login_exposed",
                    "title": "Mire d'administration WordPress standard exposée (/wp-login.php)",
                    "category": "Exposition & CMS",
                    "status": "info",
                    "severity": "low",
                    "score_weight": 5,
                    "earned_score": 2,
                    "value": "/wp-login.php accessible publiquement",
                    "message": "L'URL de connexion standard est accessible publiquement sans limitation de tentatives visible. Recommandé de la renommer (ex: WPS Hide Login) et d'activer l'authentification à deux facteurs (2FA).",
                    "remediation_key": "wp_hide_login"
                })
        except Exception:
            pass

    return {
        "cms_name": cms_name,
        "is_wordpress": is_wordpress,
        "is_shopify": is_shopify,
        "is_prestashop": is_prestashop,
        "detected_version": detected_version,
        "findings": findings
    }

