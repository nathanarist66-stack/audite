"""
DNS & Anti-Spoofing Scanner.
Inspects MX, SPF, DMARC, and DNSSEC to evaluate email security and domain protection.
"""

from typing import Dict, Any, List
import dns.resolver


def extract_apex_domain(domain: str) -> str:
    """Extracts root/apex domain from subdomain (e.g., www.facebook.com -> facebook.com)."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) > 2:
        # Common 2-level TLDs (co.uk, com.br, etc.)
        if parts[-2] in ["co", "com", "org", "net", "gov", "edu"] and len(parts[-1]) == 2:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return domain


def scan_dns_records(domain: str, timeout: float = 4.0) -> Dict[str, Any]:
    """
    Performs DNS queries for SPF, DMARC, MX, and DNSSEC.
    Includes RFC 7489 tree-walking fallback to apex domain for subdomains (e.g. www).
    """
    findings: List[Dict[str, Any]] = []
    apex_domain = extract_apex_domain(domain)
    
    # Configure resolver
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    # 1. Check MX records (query queried domain, fallback to apex)
    has_mx = False
    mx_records = []
    for d in [domain, apex_domain]:
        try:
            answers = resolver.resolve(d, "MX")
            for rdata in answers:
                mx_records.append(str(rdata.exchange).rstrip("."))
            if mx_records:
                has_mx = True
                break
        except Exception:
            continue

    # 2. Check SPF (TXT records on queried domain, fallback to apex)
    spf_record = None
    for d in [domain, apex_domain]:
        try:
            txt_answers = resolver.resolve(d, "TXT")
            for rdata in txt_answers:
                txt_content = "".join([s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s) for s in rdata.strings])
                if txt_content.lower().startswith("v=spf1"):
                    spf_record = txt_content
                    break
            if spf_record:
                break
        except Exception:
            continue

    if not spf_record:
        if has_mx:
            findings.append({
                "key": "spf_missing",
                "title": "Enregistrement SPF absent",
                "status": "fail",
                "severity": "high",
                "score_weight": 15,
                "earned_score": 0,
                "message": "Aucun enregistrement SPF trouvé alors que le domaine reçoit des emails (MX). Risque sévère de spoofing d'email.",
                "remediation_key": "dns_spf"
            })
        else:
            findings.append({
                "key": "spf_missing",
                "title": "SPF non configuré",
                "status": "warning",
                "severity": "medium",
                "score_weight": 15,
                "earned_score": 5,
                "message": "Enregistrement SPF non configuré. Même sans MX, un enregistrement neutre protège votre réputation.",
                "remediation_key": "dns_spf"
            })
    else:
        spf_lower = spf_record.lower()
        if "+all" in spf_lower:
            findings.append({
                "key": "spf_unsafe",
                "title": "SPF Dangereux (+all)",
                "status": "fail",
                "severity": "critical",
                "score_weight": 15,
                "earned_score": 0,
                "value": spf_record,
                "message": "La directive '+all' autorise TOUS les serveurs du monde à envoyer des emails en votre nom !",
                "remediation_key": "dns_spf"
            })
        elif "-all" in spf_lower:
            findings.append({
                "key": "spf_hardfail",
                "title": "SPF Robuste (Hardfail -all)",
                "status": "pass",
                "severity": "info",
                "score_weight": 15,
                "earned_score": 15,
                "value": spf_record,
                "message": "Enregistrement SPF configuré avec politique stricte (-all).",
                "remediation_key": "dns_spf"
            })
        elif "~all" in spf_lower:
            findings.append({
                "key": "spf_softfail",
                "title": "SPF Actif (Softfail ~all)",
                "status": "pass",
                "severity": "info",
                "score_weight": 15,
                "earned_score": 12,
                "value": spf_record,
                "message": "Enregistrement SPF actif en mode softfail (~all). Un passage en -all est recommandé pour un durcissement maximal.",
                "remediation_key": "dns_spf"
            })
        else:
            findings.append({
                "key": "spf_neutral",
                "title": "SPF Permissif",
                "status": "warning",
                "severity": "medium",
                "score_weight": 15,
                "earned_score": 8,
                "value": spf_record,
                "message": f"Enregistrement SPF présent mais politique neutre ou non restrictive : {spf_record}",
                "remediation_key": "dns_spf"
            })

    # 3. Check DMARC with RFC 7489 tree-walk (_dmarc.subdomain then _dmarc.apex)
    dmarc_record = None
    dmarc_source = domain
    for d in [domain, apex_domain]:
        dmarc_host = f"_dmarc.{d}"
        try:
            dmarc_answers = resolver.resolve(dmarc_host, "TXT")
            for rdata in dmarc_answers:
                txt_content = "".join([s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s) for s in rdata.strings])
                if txt_content.lower().startswith("v=dmarc1"):
                    dmarc_record = txt_content
                    dmarc_source = d
                    break
            if dmarc_record:
                break
        except Exception:
            continue

    if not dmarc_record:
        findings.append({
            "key": "dmarc_missing",
            "title": "Enregistrement DMARC absent",
            "status": "fail",
            "severity": "high",
            "score_weight": 15,
            "earned_score": 0,
            "message": "DMARC n'est pas configuré. Les pirates peuvent usurper l'identité de votre domaine sans notification.",
            "remediation_key": "dns_dmarc"
        })
    else:
        dmarc_lower = dmarc_record.lower()
        suffix_note = f" (Hérité de {apex_domain})" if dmarc_source != domain else ""
        if "p=reject" in dmarc_lower:
            findings.append({
                "key": "dmarc_reject",
                "title": f"DMARC Strict (p=reject){suffix_note}",
                "status": "pass",
                "severity": "info",
                "score_weight": 15,
                "earned_score": 15,
                "value": dmarc_record,
                "message": "Politique DMARC maximale. Les emails frauduleux sont automatiquement rejetés par les serveurs de réception.",
                "remediation_key": "dns_dmarc"
            })
        elif "p=quarantine" in dmarc_lower:
            findings.append({
                "key": "dmarc_quarantine",
                "title": f"DMARC Modéré (p=quarantine){suffix_note}",
                "status": "pass",
                "severity": "info",
                "score_weight": 15,
                "earned_score": 12,
                "value": dmarc_record,
                "message": "Politique DMARC active. Les emails non authentifiés sont envoyés dans les courriers indésirables.",
                "remediation_key": "dns_dmarc"
            })
        elif "p=none" in dmarc_lower:
            findings.append({
                "key": "dmarc_none",
                "title": f"DMARC en simple surveillance (p=none){suffix_note}",
                "status": "warning",
                "severity": "medium",
                "score_weight": 15,
                "earned_score": 6,
                "value": dmarc_record,
                "message": "La politique 'p=none' ne bloque aucune tentative de phishing ou d'usurpation.",
                "remediation_key": "dns_dmarc"
            })
        else:
            findings.append({
                "key": "dmarc_unknown",
                "title": f"DMARC configuré{suffix_note}",
                "status": "pass",
                "severity": "info",
                "score_weight": 15,
                "earned_score": 10,
                "value": dmarc_record,
                "message": f"DMARC présent : {dmarc_record}",
                "remediation_key": "dns_dmarc"
            })

    # 4. Check DNSSEC
    dnssec_active = False
    try:
        dnskey_answers = resolver.resolve(domain, "DNSKEY")
        dnssec_active = len(dnskey_answers) > 0
    except Exception:
        dnssec_active = False

    if dnssec_active:
        findings.append({
            "key": "dnssec_active",
            "title": "DNSSEC Actif",
            "status": "pass",
            "severity": "info",
            "score_weight": 10,
            "earned_score": 10,
            "message": "La zone DNS est signée cryptographiquement, protégeant contre l'empoisonnement de cache DNS (DNS Cache Poisoning).",
            "remediation_key": "dnssec"
        })
    else:
        findings.append({
            "key": "dnssec_inactive",
            "title": "DNSSEC non activé",
            "status": "info",
            "severity": "low",
            "score_weight": 10,
            "earned_score": 4,
            "message": "DNSSEC n'est pas activé sur ce nom de domaine. Recommandé pour garantir l'intégrité des résolutions DNS.",
            "remediation_key": "dnssec"
        })

    total_earned = sum(f["earned_score"] for f in findings)
    max_possible = sum(f["score_weight"] for f in findings)
    percentage = round((total_earned / max_possible) * 100) if max_possible > 0 else 0

    return {
        "score_percentage": percentage,
        "domain": domain,
        "has_mx": has_mx,
        "mx_records": mx_records,
        "spf_record": spf_record,
        "dmarc_record": dmarc_record,
        "dnssec_active": dnssec_active,
        "findings": findings
    }

