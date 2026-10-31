"""
Secret & Sensitive API Keys Scanner.
Extracts JavaScript files and HTML content to identify accidentally exposed API keys,
private tokens, and credentials (e.g., Stripe, AWS, GitHub, Slack, Firebase, SendGrid).
"""

import re
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import httpx

# High-fidelity regex signatures for exposed secrets
SECRET_SIGNATURES = [
    {
        "key": "secret_stripe_live",
        "name": "Clé Secrète Stripe (Live)",
        "pattern": r"(?:sk_live_[0-9a-zA-Z]{24,34}|rk_live_[0-9a-zA-Z]{24,34})",
        "severity": "critical",
        "weight": 35,
        "desc": "Une clé secrète Stripe de PRODUCTION est exposée publiquement. N'importe qui peut prélever ou rembourser vos clients !"
    },
    {
        "key": "secret_github_pat",
        "name": "Personal Access Token GitHub",
        "pattern": r"(?:ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{60,82})",
        "severity": "critical",
        "weight": 35,
        "desc": "Un token d'accès GitHub personnel est visible. Risque d'accès complet en lecture/écriture à vos dépôts de code privé."
    },
    {
        "key": "secret_aws_key",
        "name": "Clé d'accès AWS (Access Key ID)",
        "pattern": r"(?:AKIA[0-9A-Z]{16})",
        "severity": "critical",
        "weight": 30,
        "desc": "Un identifiant d'accès AWS (IAM) est divulgué dans le frontend. Risque d'accès illégitime à votre infrastructure cloud."
    },
    {
        "key": "secret_slack_token",
        "name": "Token de Bot / API Slack",
        "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}",
        "severity": "high",
        "weight": 25,
        "desc": "Un token d'intégration Slack est exposé. Permet de lire et d'envoyer des messages sur vos canaux d'entreprise."
    },
    {
        "key": "secret_sendgrid_key",
        "name": "Clé API SendGrid",
        "pattern": r"SG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43}",
        "severity": "high",
        "weight": 25,
        "desc": "Une clé d'envoi d'e-mails SendGrid est divulguée. Des attaquants peuvent envoyer des campagnes de phishing en votre nom."
    },
    {
        "key": "secret_rsa_private_key",
        "name": "Clé Privée RSA / SSH",
        "pattern": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
        "severity": "critical",
        "weight": 40,
        "desc": "Une clé cryptographique privée est présente en clair dans le code client !"
    },
    {
        "key": "secret_supabase_service_role",
        "name": "Clé Supabase 'service_role' (Admin)",
        "pattern": r"eyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}",
        "severity": "critical",
        "weight": 35,
        "desc": "Un token JWT ressemblant à une clé d'administration Supabase 'service_role' a été identifié. Cette clé outrepasse les règles Row-Level Security !"
    }
]


def mask_secret(secret: str) -> str:
    """Masks secret to reveal only prefix and last 4 characters for safe display."""
    if len(secret) <= 8:
        return "****"
    return secret[:6] + "..." + secret[-4:]


async def scan_for_secrets(
    html_content: str,
    base_url: str,
    client: httpx.AsyncClient,
    max_scripts_to_fetch: int = 5
) -> Dict[str, Any]:
    """
    Parses scripts from HTML and inspects their content for hardcoded secrets.
    """
    findings = []
    scanned_scripts_count = 0
    detected_secrets_count = 0

    if not html_content:
        return {
            "score_percentage": 100,
            "detected_secrets": [],
            "findings": findings,
            "scripts_scanned": 0
        }

    # Extract inline scripts and external JS links
    soup = BeautifulSoup(html_content, "html.parser")
    script_texts = []
    
    # 1. Inline scripts in homepage HTML
    for s in soup.find_all("script"):
        if s.string and len(s.string.strip()) > 10:
            script_texts.append(("Inline script (HTML)", s.string))

    # 2. External JS scripts (limit to priority app bundles, avoiding standard CDNs like cdnjs/google)
    base_parsed = urlparse(base_url)
    ext_scripts = []
    for s in soup.find_all("script", src=True):
        src = s["src"].strip()
        if not src:
            continue
        full_url = urljoin(base_url, src)
        parsed = urlparse(full_url)
        # Prioritize first-party scripts (e.g. /static/js/main.js, /_next/static/...)
        if parsed.netloc == base_parsed.netloc or not parsed.netloc:
            ext_scripts.append(full_url)

    # Fetch top external scripts concurrently
    for script_url in ext_scripts[:max_scripts_to_fetch]:
        try:
            resp = await client.get(script_url, timeout=3.5)
            if resp.status_code == 200 and resp.text:
                script_texts.append((script_url, resp.text))
                scanned_scripts_count += 1
        except Exception:
            continue

    # Inspect all collected scripts against signatures
    found_keys = set()
    for source_name, content in script_texts:
        for sig in SECRET_SIGNATURES:
            # Special check for Supabase: only alert if the JWT explicitly contains "service_role"
            if sig["key"] == "secret_supabase_service_role":
                if "service_role" not in content:
                    continue

            matches = re.findall(sig["pattern"], content)
            if matches:
                # Deduplicate matches
                unique_match = matches[0]
                dedup_key = f"{sig['key']}_{unique_match}"
                if dedup_key in found_keys:
                    continue
                found_keys.add(dedup_key)
                detected_secrets_count += 1

                masked = mask_secret(unique_match)
                findings.append({
                    "key": sig["key"],
                    "title": f"FUITE CRITIQUE : {sig['name']} détectée !",
                    "category": "Clés d'API & Secrets",
                    "status": "fail",
                    "severity": sig["severity"],
                    "score_weight": sig["weight"],
                    "earned_score": 0,
                    "value": f"{masked} (Fichier: {source_name})",
                    "message": f"{sig['desc']} Fichier source : {source_name}",
                    "remediation_key": "revoke_exposed_secrets"
                })

    # If no secrets found, award full score bonus
    if detected_secrets_count == 0:
        findings.append({
            "key": "no_secrets_leaked",
            "title": "Aucune clé d'API ou secret d'authentification exposé",
            "category": "Clés d'API & Secrets",
            "status": "pass",
            "severity": "info",
            "score_weight": 15,
            "earned_score": 15,
            "message": f"Contrôle anti-fuite réussi sur {len(script_texts)} scripts inspectés (aucun token Stripe, AWS, GitHub ou Supabase détecté).",
            "remediation_key": "revoke_exposed_secrets"
        })

    score_pct = max(0, 100 - (detected_secrets_count * 40))

    return {
        "score_percentage": score_pct,
        "detected_count": detected_secrets_count,
        "scripts_scanned": len(script_texts),
        "findings": findings
    }
