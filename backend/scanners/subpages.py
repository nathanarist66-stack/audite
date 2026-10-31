"""
Smart Sub-Pages & Critical Endpoints Security Scanner.
Extracts internal links from HTML and audits priority pages:
- Authentication & Login pages (/login, /signin, /connexion)
- Administration portals (/admin, /wp-login.php, /dashboard)
- Contact & Inquiry forms (/contact)
"""

from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import httpx

PRIORITY_KEYWORDS = ["login", "signin", "connexion", "auth", "admin", "contact", "compte", "dashboard"]


def discover_critical_subpages(html_content: str, base_url: str) -> List[str]:
    """Finds up to 4 critical internal endpoints referenced on the homepage."""
    if not html_content:
        return []
    
    base_netloc = urlparse(base_url).netloc
    soup = BeautifulSoup(html_content, "html.parser")
    found_urls = set()

    for a in soup.find_all("a", href=True):
        href = a.get("href", "").strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        
        full_url = urljoin(base_url, href)
        parsed = urlparse(full_url)
        
        # Only internal links
        if parsed.netloc == base_netloc and parsed.path:
            path_lower = parsed.path.lower()
            if any(k in path_lower for k in PRIORITY_KEYWORDS):
                clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                found_urls.add(clean)
                if len(found_urls) >= 4:
                    break

    # If no links discovered, add common defaults
    if not found_urls:
        defaults = ["/login", "/admin", "/contact"]
        for d in defaults:
            found_urls.add(urljoin(base_url, d))

    return list(found_urls)[:3]


async def audit_subpages(subpage_urls: List[str], client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    """Tests critical subpages for HTTPS encryption, response status, and form safety."""
    results = []
    
    for url in subpage_urls:
        parsed = urlparse(url)
        path = parsed.path or "/"
        try:
            resp = await client.get(url, timeout=3.5, follow_redirects=True)
            has_password = False
            has_form = False
            
            if resp.status_code == 200 and "text/html" in resp.headers.get("content-type", ""):
                soup = BeautifulSoup(resp.text, "html.parser")
                has_password = bool(soup.find("input", {"type": "password"}))
                has_form = bool(soup.find("form"))

            results.append({
                "url": url,
                "path": path,
                "status_code": resp.status_code,
                "is_https": str(resp.url).startswith("https://"),
                "has_login_form": has_password,
                "has_form": has_form,
                "status": "secure" if str(resp.url).startswith("https://") else "warning"
            })
        except Exception:
            results.append({
                "url": url,
                "path": path,
                "status_code": 0,
                "is_https": url.startswith("https://"),
                "has_login_form": False,
                "has_form": False,
                "status": "unreachable"
            })
            
    return results

