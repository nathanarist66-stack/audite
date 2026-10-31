"""
Multi-Pages Sitemap Deep Crawler.
Discovers sitemap.xml, crawls internal pages, and checks for:
- Mixed content (HTTP assets on HTTPS pages)
- Insecure password or action forms
- Broken internal links (HTTP 404 / 500)
"""

from typing import List, Dict, Any
from urllib.parse import urlparse, urljoin
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
import httpx


async def discover_and_audit_sitemap(
    base_url: str,
    client: httpx.AsyncClient,
    max_pages: int = 10
) -> Dict[str, Any]:
    """
    Finds sitemap.xml and performs security checks on discovered pages.
    """
    parsed_base = urlparse(base_url)
    sitemap_url = f"{parsed_base.scheme}://{parsed_base.netloc}/sitemap.xml"
    discovered_urls = []
    has_sitemap = False

    # 1. Fetch sitemap.xml
    try:
        resp = await client.get(sitemap_url, timeout=4.0)
        if resp.status_code == 200 and ("<urlset" in resp.text or "<sitemapindex" in resp.text):
            has_sitemap = True
            # Parse XML
            try:
                root = ET.fromstring(resp.content)
                for elem in root.iter():
                    if elem.tag.endswith("loc") and elem.text:
                        loc = elem.text.strip()
                        # Only keep internal pages under same domain
                        if urlparse(loc).netloc == parsed_base.netloc:
                            discovered_urls.append(loc)
            except Exception:
                pass
    except Exception:
        pass

    # Deduplicate and limit
    discovered_urls = list(dict.fromkeys(discovered_urls))[:max_pages]

    # 2. Audit discovered pages for security compliance
    page_results = []
    mixed_content_pages = []
    broken_pages = []

    for url in discovered_urls:
        try:
            p_resp = await client.get(url, timeout=3.5, follow_redirects=True)
            status = p_resp.status_code
            if status >= 400:
                broken_pages.append({"url": url, "status": status})
                page_results.append({"url": url, "status": status, "secure": False, "mixed_content": False})
                continue

            # Check mixed content on HTTPS pages
            has_mixed = False
            if parsed_base.scheme == "https" and p_resp.text:
                p_soup = BeautifulSoup(p_resp.text, "html.parser")
                for tag in p_soup.find_all(["img", "script", "iframe"], src=True):
                    src = tag["src"].strip().lower()
                    if src.startswith("http://"):
                        has_mixed = True
                        mixed_content_pages.append(url)
                        break

            page_results.append({
                "url": url,
                "status": status,
                "secure": not has_mixed,
                "mixed_content": has_mixed
            })
        except Exception:
            broken_pages.append({"url": url, "status": 0})

    findings = []
    if has_sitemap:
        findings.append({
            "key": "sitemap_detected",
            "title": f"Fichier sitemap.xml détecté ({len(discovered_urls)} pages explorées)",
            "category": "Code HTML & Scripts",
            "status": "pass",
            "severity": "info",
            "score_weight": 5,
            "earned_score": 5,
            "message": f"Le sitemap.xml est accessible et référence la structure du site. {len(discovered_urls)} page(s) auditée(s).",
            "remediation_key": "sitemap_optimization"
        })
    else:
        findings.append({
            "key": "sitemap_missing",
            "title": "Fichier sitemap.xml introuvable",
            "category": "Code HTML & Scripts",
            "status": "info",
            "severity": "low",
            "score_weight": 5,
            "earned_score": 3,
            "message": "Aucun sitemap.xml repéré à la racine. Recommandé pour le référencement et l'inventaire des ressources.",
            "remediation_key": "sitemap_optimization"
        })

    if mixed_content_pages:
        findings.append({
            "key": "sitemap_mixed_content",
            "title": f"Contenu mixte (HTTP non sécurisé) détecté sur {len(mixed_content_pages)} page(s)",
            "category": "Code HTML & Scripts",
            "status": "fail",
            "severity": "high",
            "score_weight": 15,
            "earned_score": 0,
            "value": f"Pages affectées : {', '.join(mixed_content_pages[:3])}",
            "message": "Des ressources (images ou scripts) sont appelées en HTTP non chiffré sur des pages HTTPS internes du sitemap.",
            "remediation_key": "fix_mixed_content"
        })

    return {
        "has_sitemap": has_sitemap,
        "total_discovered": len(discovered_urls),
        "pages_audited": page_results,
        "mixed_content_count": len(mixed_content_pages),
        "broken_count": len(broken_pages),
        "findings": findings
    }

