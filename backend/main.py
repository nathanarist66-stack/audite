"""
Audite - Plateforme d'Audit et de Remédiation de Sécurité Web.
FastAPI Application Backend.
"""

import asyncio
import ipaddress
import socket
import csv
import io
import time
from urllib.parse import urlparse
from typing import Optional, List, Dict
from collections import defaultdict

from fastapi import FastAPI, HTTPException, Query, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import httpx

from .scanners.headers import scan_security_headers
from .scanners.ssl_scanner import scan_ssl_tls
from .scanners.dns_scanner import scan_dns_records
from .scanners.leaks_scanner import scan_information_leaks
from .scanners.html_scanner import scan_html_security
from .scanners.subpages import discover_critical_subpages, audit_subpages
from .scanners.secrets_scanner import scan_for_secrets
from .scanners.privacy_scanner import scan_privacy_gdpr
from .scanners.reputation_scanner import scan_ip_reputation
from .scanners.sitemap_scanner import discover_and_audit_sitemap
from .alerts import send_security_alert, send_test_webhook
from .scoring import compile_audit_report
from .badge import generate_svg_badge
from .patch_generator import generate_unified_patch
from .db import (
    save_audit,
    get_audit_by_id,
    get_latest_audit_by_domain,
    get_recent_audits,
    get_domain_history,
    add_monitored_domain,
    get_all_monitored_domains,
    delete_monitored_domain,
    update_monitored_domain_status,
    update_monitored_webhook,
    save_lead,
    get_all_leads,
    delete_lead
)

app = FastAPI(
    title="Audite Security Engine API",
    description="Moteur d'audit passif de vulnérabilités web et recommandations de remédiation.",
    version="1.0.0"
)

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate Limiter Middleware (Anti-DDoS / Anti-Brute-Force for Public Deployment)
RATE_LIMIT_STORE = defaultdict(list)
MAX_REQUESTS_PER_MINUTE = 40

@app.middleware("http")
async def rate_limiting_middleware(request: Request, call_next):
    # Only rate-limit heavy audit endpoints
    path = request.url.path
    if path in ["/api/audit", "/api/compare"]:
        client_ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()
        # Clean timestamps older than 60s
        timestamps = [t for t in RATE_LIMIT_STORE[client_ip] if now - t < 60]
        if len(timestamps) >= MAX_REQUESTS_PER_MINUTE:
            return Response(
                content='{"detail": "Trop de requêtes d\'audit envoyées. Veuillez patienter une minute avant de réessayer."}',
                status_code=429,
                media_type="application/json"
            )
        timestamps.append(now)
        RATE_LIMIT_STORE[client_ip] = timestamps

    response = await call_next(request)
    # Security Response Headers (Audite self-hardening)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' 'unsafe-inline' 'unsafe-eval' https: data:; "
        "font-src 'self' https: data:; "
        "img-src 'self' https: data:;"
    )
    return response


class AuditRequest(BaseModel):
    url: str = Field(..., description="L'URL du site web à auditer (ex: https://example.com)")


class CompareRequest(BaseModel):
    url1: str = Field(..., description="Première URL à comparer")
    url2: str = Field(..., description="Deuxième URL à comparer")


class MonitorRequest(BaseModel):
    url: str = Field(..., description="URL ou domaine à ajouter à la surveillance")
    webhook_url: Optional[str] = Field(None, description="URL Webhook Discord / Slack pour alertes")


class WebhookTestRequest(BaseModel):
    webhook_url: str = Field(..., description="URL Webhook Discord / Slack à tester")


class LeadCaptureRequest(BaseModel):
    email: str = Field(..., description="Email professionnel du prospect")
    domain: str = Field(..., description="Domaine audité")
    audit_id: Optional[str] = Field(None, description="Identifiant unique de l'audit")
    global_score: Optional[int] = Field(0, description="Score global obtenu")
    grade: Optional[str] = Field("N/A", description="Note obtenue")
    critical_count: Optional[int] = Field(0, description="Nombre de failles critiques")
    notes: Optional[str] = Field("", description="Remarques éventuelles")


def validate_and_sanitize_url(raw_url: str):
    """
    Validates URL, checks scheme and protects against SSRF attacks.
    """
    raw_url = raw_url.strip()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)
    hostname = parsed.hostname

    if not hostname:
        raise HTTPException(status_code=400, detail="Nom de domaine ou URL invalide.")

    # Prevent localhost & SSRF probes against internal networks
    try:
        resolved_ips = socket.getaddrinfo(hostname, None)
        for family, socktype, proto, canonname, sockaddr in resolved_ips:
            ip_str = sockaddr[0]
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                raise HTTPException(
                    status_code=400,
                    detail="L'analyse des adresses IP locales, privées ou de boucle locale est interdite par sécurité (SSRF)."
                )
    except socket.gaierror:
        raise HTTPException(status_code=400, detail=f"Impossible de résoudre le nom de domaine '{hostname}'. Vérifiez l'orthographe.")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return raw_url, parsed.scheme, hostname, port


@app.get("/api/health")
async def health_check():
    return {"status": "ok", "service": "audite-engine", "version": "1.0.0"}


@app.get("/api/reports/recent")
async def get_recent_reports(limit: int = 8):
    """Returns the most recent audits for the homepage feed."""
    return get_recent_audits(limit=limit)


@app.get("/api/badge/{domain:path}")
@app.get("/badge/{domain:path}")
async def get_domain_badge(domain: str):
    """Returns a dynamic SVG security badge for website embedding."""
    clean_domain = domain.lower().replace(".svg", "").replace("https://", "").replace("http://", "").split("/")[0]
    report = get_latest_audit_by_domain(clean_domain)
    
    if report:
        svg_content = generate_svg_badge(
            grade=report.get("grade", "C"),
            score=report.get("global_score", 0),
            color_type=report.get("grade_color", "emerald")
        )
    else:
        svg_content = generate_svg_badge(
            grade="Non Audité",
            score=-1,
            color_type="gray"
        )
        
    return Response(
        content=svg_content,
        media_type="image/svg+xml",
        headers={"Cache-Control": "public, max-age=300"}
    )


@app.get("/api/patch/{domain}")
async def get_auto_patch(domain: str, platform: str = Query("firebase", description="firebase, nginx, apache, nodejs, nextjs")):
    """Generates a complete, single-file security patch for the requested web server."""
    clean_domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
    report = get_latest_audit_by_domain(clean_domain)
    if not report:
        raise HTTPException(status_code=404, detail="Aucun rapport disponible pour ce domaine. Lancez un audit d'abord.")
    
    patch = generate_unified_patch(report.get("findings", []), platform=platform)
    return patch


from backend.remediations import REMEDIATIONS_DB

def enrich_report_remediations(report: dict) -> dict:
    """Enriches report findings with the latest snippets from REMEDIATIONS_DB."""
    if not report or "findings" not in report:
        return report
    for finding in report.get("findings", []):
        rem_key = finding.get("remediation_key") or finding.get("key")
        if rem_key in REMEDIATIONS_DB:
            finding["remediation"] = REMEDIATIONS_DB[rem_key]
    return report


@app.get("/api/reports/{identifier}")
async def get_single_report(identifier: str):
    """Retrieves an audit report by ID (e.g. aud_123) or by domain (e.g. facebook.com)."""
    if identifier.startswith("aud_"):
        report = get_audit_by_id(identifier)
    else:
        report = get_latest_audit_by_domain(identifier)
    
    if not report:
        raise HTTPException(status_code=404, detail="Rapport d'audit introuvable.")
    return enrich_report_remediations(report)


@app.post("/api/audit")
async def run_audit(req: AuditRequest):
    return await execute_audit(req.url, deep_scan=False)


@app.post("/api/audit/deep")
async def run_deep_audit(req: AuditRequest):
    """Executes a deep multi-pages crawl using sitemap.xml."""
    return await execute_audit(req.url, deep_scan=True)


@app.get("/api/audit")
async def run_audit_get(url: str = Query(..., description="URL cible")):
    return await execute_audit(url, deep_scan=False)


async def execute_audit(raw_url: str, deep_scan: bool = False):
    """
    Orchestrates parallel security audits on the target domain.
    """
    clean_url, scheme, hostname, port = validate_and_sanitize_url(raw_url)
    is_https = (scheme == "https")

    # 1. SSL/TLS Audit: target port 443 unless explicit custom port was provided in URL
    ssl_port = parsed_port = port
    if not is_https and port == 80:
        ssl_port = 443

    loop = asyncio.get_running_loop()
    ssl_timeout = 5.0 if is_https else 3.0
    ssl_task = loop.run_in_executor(None, scan_ssl_tls, hostname, ssl_port, ssl_timeout)

    # 2. DNS Audit (Run in thread pool for DNS resolver queries)
    dns_task = loop.run_in_executor(None, scan_dns_records, hostname, 4.0)

    # 3. IP Reputation & DNSBL Blacklist check (Run in thread pool)
    reputation_task = loop.run_in_executor(None, scan_ip_reputation, hostname, 2.5)

    # 4. HTTP Request, Headers, HTML, Secrets, Privacy & Subpages Audit (Async HTTPX)
    html_content = ""
    subpages_results = []
    secrets_res = {"score_percentage": 100, "findings": [], "detected_count": 0}
    privacy_res = {"score_percentage": 100, "findings": [], "trackers": []}
    sitemap_res = {"findings": []}

    async with httpx.AsyncClient(
        verify=False,  # We want to capture headers even if cert is self-signed/expired to diagnose it
        follow_redirects=True,
        timeout=httpx.Timeout(6.0, connect=4.0),
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AuditeSecurityBot/1.0"}
    ) as client:
        try:
            response = await client.get(clean_url)
            response_headers = dict(response.headers)
            status_code = response.status_code
            html_content = response.text
        except Exception:
            response_headers = {}
            status_code = 0

        # Scan headers
        headers_res = scan_security_headers(response_headers, is_https=is_https)

        # Scan HTML & client-side scripts
        html_res = scan_html_security(html_content, clean_url, is_https=is_https)

        # If main server is alive, perform deeper probes; otherwise skip to avoid cascading timeouts
        if status_code != 0:
            leaks_res = await scan_information_leaks(clean_url, response_headers, client)
            secrets_res = await scan_for_secrets(html_content, clean_url, client)
            privacy_res = await scan_privacy_gdpr(clean_url, html_content, response_headers, client)
            
            if deep_scan:
                sitemap_res = await discover_and_audit_sitemap(clean_url, client)

            try:
                discovered_pages = discover_critical_subpages(html_content, clean_url)
                subpages_results = await audit_subpages(discovered_pages, client)
            except Exception:
                subpages_results = []
        else:
            leaks_res = {
                "score_percentage": 0,
                "server_header": None,
                "powered_by": None,
                "has_security_txt": False,
                "findings": [{
                    "key": "server_unreachable",
                    "title": "Serveur Web Inaccessible",
                    "category": "Empreintes & Fuites",
                    "status": "fail",
                    "severity": "critical",
                    "score_weight": 20,
                    "earned_score": 0,
                    "message": "Le serveur n'a renvoyé aucune réponse HTTP (délai de connexion dépassé ou serveur hors-ligne).",
                    "remediation_key": "server_tokens"
                }]
            }
            subpages_results = []

    # Await concurrent SSL, DNS and Reputation tasks
    ssl_res, dns_res, reputation_res = await asyncio.gather(ssl_task, dns_task, reputation_task)

    # Compile comprehensive report
    report = compile_audit_report(
        target_url=clean_url,
        headers_res=headers_res,
        ssl_res=ssl_res,
        dns_res=dns_res,
        leaks_res=leaks_res,
        html_res=html_res,
        secrets_res=secrets_res,
        privacy_res=privacy_res,
        reputation_res=reputation_res,
        sitemap_res=sitemap_res
    )
    report["http_status"] = status_code
    report["domain"] = hostname
    report["subpages"] = subpages_results

    # Check for previous audit to calculate Time-Travel progression & regressions
    previous_audit = get_latest_audit_by_domain(hostname)
    score_delta = None
    if previous_audit:
        prev_score = previous_audit.get("global_score", 0)
        score_delta = report["global_score"] - prev_score
        
        # Compare resolved findings
        prev_fails = {f.get("key"): f.get("title") for f in previous_audit.get("findings", []) if f.get("status") != "pass"}
        current_passes = {f.get("key") for f in report.get("findings", []) if f.get("status") == "pass"}
        resolved_keys = prev_fails.keys() & current_passes
        resolved_titles = [prev_fails[k] for k in resolved_keys]

        report["progression"] = {
            "has_previous": True,
            "previous_score": prev_score,
            "previous_grade": previous_audit.get("grade", "C"),
            "previous_date": previous_audit.get("created_at"),
            "score_delta": score_delta,
            "resolved_count": len(resolved_keys),
            "resolved_titles": resolved_titles[:4]
        }
    else:
        report["progression"] = {"has_previous": False}

    # Save to SQLite database
    audit_id = save_audit(report)
    report["audit_id"] = audit_id
    report["history"] = get_domain_history(hostname, limit=5)

    # Update monitored domain metrics if domain is monitored
    ssl_info = report.get("pillars", {}).get("ssl", {})
    update_monitored_domain_status(
        domain=hostname,
        score=report.get("global_score", 0),
        grade=report.get("grade", "C"),
        ssl_days=ssl_info.get("expires_in_days"),
        ssl_issuer=ssl_info.get("issuer")
    )

    # Automated alert dispatching if monitored with webhook
    all_monitored = get_all_monitored_domains()
    mon_match = next((m for m in all_monitored if m["domain"] == hostname), None)
    if mon_match and mon_match.get("webhook_url"):
        w_url = mon_match["webhook_url"]
        # Trigger 1: SSL Expiration alert (<= 7 days)
        ssl_days = ssl_info.get("expires_in_days")
        if ssl_days is not None and ssl_days <= 7:
            asyncio.create_task(send_security_alert(
                domain=hostname,
                event_type="ssl_expiring",
                title="Expiration Imminente du Certificat SSL !",
                message=f"Le certificat SSL du site `{hostname}` expire dans {ssl_days} jour(s). Renouvelez-le d'urgence pour éviter le blocage par les navigateurs.",
                score=report["global_score"],
                grade=report["grade"],
                webhook_url=w_url,
                days_left=ssl_days
            ))
        # Trigger 2: Secret Leaks alert
        if secrets_res.get("detected_count", 0) > 0:
            asyncio.create_task(send_security_alert(
                domain=hostname,
                event_type="secret_leak",
                title="ALERTE CRITIQUE : Clé Secrète / Token Détecté !",
                message=f"{secrets_res['detected_count']} clé(s) sensible(s) ou token(s) d'accès ont été découverts dans le code JavaScript de `{hostname}`.",
                score=report["global_score"],
                grade=report["grade"],
                webhook_url=w_url
            ))
        # Trigger 3: Severe score regression
        if score_delta is not None and score_delta <= -15:
            asyncio.create_task(send_security_alert(
                domain=hostname,
                event_type="score_regression",
                title="Chute Sévère de la Note de Sécurité !",
                message=f"Le score de `{hostname}` a chuté de {abs(score_delta)} points (Score actuel : {report['global_score']}/100, Note : {report['grade']}).",
                score=report["global_score"],
                grade=report["grade"],
                webhook_url=w_url
            ))

    return report


@app.get("/api/reports/{identifier}/csv")
async def export_report_csv(identifier: str):
    """Exports audit findings in CSV format (UTF-8 with BOM for Excel compatibility)."""
    if identifier.startswith("aud_"):
        report = get_audit_by_id(identifier)
    else:
        report = get_latest_audit_by_domain(identifier)
    if not report:
        raise HTTPException(status_code=404, detail="Rapport introuvable pour l'export CSV.")
    
    report = enrich_report_remediations(report)
    domain = report.get("domain", "audit")
    created_at = report.get("created_at", "")
    score = report.get("global_score", 0)
    grade = report.get("grade", "C")

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)
    writer.writerow([
        "Domaine", "Date Audit", "Score Global", "Note", "Catégorie", "Titre",
        "Statut", "Sévérité", "Impact Score", "Message", "Référence OWASP", "Référence CWE", "Valeur Détectée"
    ])

    for f in report.get("findings", []):
        rem = f.get("remediation", {})
        writer.writerow([
            domain,
            created_at,
            score,
            grade,
            f.get("category", ""),
            f.get("title", ""),
            f.get("status", ""),
            f.get("severity", ""),
            f.get("score_weight", 0),
            f.get("message", ""),
            rem.get("owasp", "N/A"),
            rem.get("cwe", "N/A"),
            f.get("value", "")
        ])

    csv_bytes = output.getvalue().encode("utf-8-sig")
    return Response(
        content=csv_bytes,
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=audite-rapport-{domain}.csv"
        }
    )


@app.post("/api/compare")
async def compare_sites(req: CompareRequest):
    """
    Audits two domains in parallel and returns side-by-side comparison metrics.
    """
    task1 = execute_audit(req.url1)
    task2 = execute_audit(req.url2)
    report1, report2 = await asyncio.gather(task1, task2)
    
    score1 = report1.get("global_score", 0)
    score2 = report2.get("global_score", 0)
    domain1 = report1.get("domain", req.url1)
    domain2 = report2.get("domain", req.url2)
    
    if score1 > score2:
        winner = domain1
        diff = score1 - score2
        summary_msg = f"{domain1} est plus sécurisé que {domain2} (+{diff} points d'avance)."
    elif score2 > score1:
        winner = domain2
        diff = score2 - score1
        summary_msg = f"{domain2} est plus sécurisé que {domain1} (+{diff} points d'avance)."
    else:
        winner = "Égalité"
        diff = 0
        summary_msg = "Les deux sites affichent un niveau de sécurité rigoureusement équivalent."
        
    return {
        "site1": report1,
        "site2": report2,
        "comparison": {
            "winner": winner,
            "delta_points": diff,
            "summary_message": summary_msg,
            "pillars": {
                "headers": {"site1": report1.get("pillars", {}).get("headers", {}).get("score", 0), "site2": report2.get("pillars", {}).get("headers", {}).get("score", 0)},
                "ssl": {"site1": report1.get("pillars", {}).get("ssl", {}).get("score", 0), "site2": report2.get("pillars", {}).get("ssl", {}).get("score", 0)},
                "dns": {"site1": report1.get("pillars", {}).get("dns", {}).get("score", 0), "site2": report2.get("pillars", {}).get("dns", {}).get("score", 0)},
                "html": {"site1": report1.get("pillars", {}).get("html", {}).get("score", 0), "site2": report2.get("pillars", {}).get("html", {}).get("score", 0)},
                "leaks": {"site1": report1.get("pillars", {}).get("leaks", {}).get("score", 0), "site2": report2.get("pillars", {}).get("leaks", {}).get("score", 0)}
            },
            "metrics": [
                {"label": "Protocole Chiffrement", "site1": report1.get("pillars", {}).get("ssl", {}).get("protocol") or "SSL Inactif", "site2": report2.get("pillars", {}).get("ssl", {}).get("protocol") or "SSL Inactif"},
                {"label": "Émetteur du Certificat", "site1": report1.get("pillars", {}).get("ssl", {}).get("issuer") or "Manquant", "site2": report2.get("pillars", {}).get("ssl", {}).get("issuer") or "Manquant"},
                {"label": "Expiration Certificat", "site1": f"{report1.get('pillars', {}).get('ssl', {}).get('expires_in_days', 0)} jours" if report1.get('pillars', {}).get('ssl', {}).get('expires_in_days') is not None else "N/A", "site2": f"{report2.get('pillars', {}).get('ssl', {}).get('expires_in_days', 0)} jours" if report2.get('pillars', {}).get('ssl', {}).get('expires_in_days') is not None else "N/A"},
                {"label": "Protection SPF (Email)", "site1": "Actif" if report1.get("pillars", {}).get("dns", {}).get("has_spf") else "Inexistant", "site2": "Actif" if report2.get("pillars", {}).get("dns", {}).get("has_spf") else "Inexistant"},
                {"label": "Configuration DMARC", "site1": "Configuré" if report1.get("pillars", {}).get("dns", {}).get("has_dmarc") else "Manquant", "site2": "Configuré" if report2.get("pillars", {}).get("dns", {}).get("has_dmarc") else "Manquant"},
                {"label": "Failles Critiques", "site1": report1.get("summary", {}).get("critical", 0), "site2": report2.get("summary", {}).get("critical", 0)},
                {"label": "Failles Élevées", "site1": report1.get("summary", {}).get("high", 0), "site2": report2.get("summary", {}).get("high", 0)}
            ]
        }
    }


@app.post("/api/monitor")
async def add_monitor_endpoint(req: MonitorRequest):
    """Adds a domain to active monitoring watchlist with optional webhook."""
    domain = req.url.lower().replace("https://", "").replace("http://", "").split("/")[0]
    res = add_monitored_domain(domain=domain, url=req.url, webhook_url=req.webhook_url)
    return res


@app.post("/api/monitor/test-webhook")
async def test_webhook_route(req: WebhookTestRequest):
    """Sends a test alert to verify Discord or Slack webhook URL."""
    ok = await send_test_webhook(req.webhook_url)
    if not ok:
        raise HTTPException(status_code=400, detail="Échec de l'envoi du test. Vérifiez que l'URL du webhook est valide.")
    return {"status": "ok", "message": "Notification de test envoyée avec succès sur votre canal !"}


@app.get("/api/monitor")
async def list_monitored_endpoints():
    """Lists all monitored domains and their security status."""
    return get_all_monitored_domains()


@app.delete("/api/monitor/{domain_or_id}")
async def delete_monitor_endpoint(domain_or_id: str):
    """Deletes a domain from monitoring watchlist."""
    success = delete_monitored_domain(domain_or_id)
    if not success:
        raise HTTPException(status_code=404, detail="Domaine introuvable dans la liste de surveillance.")
    return {"status": "deleted", "target": domain_or_id}


@app.post("/api/monitor/check-all")
async def check_all_monitors():
    """Re-scans all monitored domains to update metrics and detect regressions/expirations."""
    monitors = get_all_monitored_domains()
    results = []
    for m in monitors:
        try:
            report = await execute_audit(m["url"])
            ssl_info = report.get("pillars", {}).get("ssl", {})
            update_monitored_domain_status(
                domain=m["domain"],
                score=report.get("global_score", 0),
                grade=report.get("grade", "C"),
                ssl_days=ssl_info.get("expires_in_days"),
                ssl_issuer=ssl_info.get("issuer")
            )
            results.append({"domain": m["domain"], "status": "updated", "score": report.get("global_score")})
        except Exception as e:
            results.append({"domain": m["domain"], "status": "error", "error": str(e)})
    return {"checked": len(results), "items": get_all_monitored_domains()}


@app.post("/api/leads")
async def capture_lead_endpoint(req: LeadCaptureRequest):
    """Enregistre un prospect qualifié ayant demandé le rapport d'audit par email."""
    if "@" not in req.email or "." not in req.email:
        raise HTTPException(status_code=400, detail="Veuillez fournir une adresse email valide.")
    lead = save_lead(
        email=req.email,
        domain=req.domain,
        audit_id=req.audit_id,
        global_score=req.global_score or 0,
        grade=req.grade or "N/A",
        critical_count=req.critical_count or 0,
        notes=req.notes or ""
    )
    return {
        "status": "ok",
        "message": f"Rapport officiel programmé pour envoi à {req.email}. Merci de votre confiance !",
        "lead": lead
    }


@app.get("/api/leads")
async def list_leads_endpoint():
    """Liste tous les prospects capturés via le Lead Magnet."""
    return get_all_leads()


@app.delete("/api/leads/{lead_id}")
async def delete_lead_endpoint(lead_id: str):
    """Supprime un prospect de la base de données."""
    success = delete_lead(lead_id)
    if not success:
        raise HTTPException(status_code=404, detail="Prospect introuvable.")
    return {"status": "deleted", "id": lead_id}


@app.get("/api/leads/export/csv")
async def export_leads_csv():
    """Exporte la liste complète des prospects au format CSV exploitable dans Excel ou CRM."""
    leads = get_all_leads()
    output = io.StringIO()
    writer = csv.writer(output, delimiter=";")
    writer.writerow(["ID", "Email", "Domaine", "Score", "Grade", "Failles_Critiques", "Date_Capture"])
    for l in leads:
        writer.writerow([
            l.get("id", ""),
            l.get("email", ""),
            l.get("domain", ""),
            l.get("global_score", 0),
            l.get("grade", "N/A"),
            l.get("critical_count", 0),
            l.get("created_at", "")
        ])
    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=prospects_audite.csv"}
    )


# Mount static files if frontend build exists
import os
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
