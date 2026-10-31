"""
IP Reputation & DNSBL (Blacklist) Security Scanner.
Checks if the target server's IPv4 address is listed on major global anti-spam / abuse blacklists:
- Spamhaus ZEN (zen.spamhaus.org)
- SpamCop (bl.spamcop.net)
- Barracuda (b.barracudacentral.org)
"""

import socket
from typing import Dict, Any, List
import dns.resolver

DNSBL_SERVERS = [
    {"name": "Spamhaus ZEN", "zone": "zen.spamhaus.org"},
    {"name": "SpamCop RBL", "zone": "bl.spamcop.net"},
    {"name": "Barracuda Reputation Network", "zone": "b.barracudacentral.org"}
]


def scan_ip_reputation(hostname: str, timeout: float = 2.5) -> Dict[str, Any]:
    """
    Resolves hostname to IP, reverses octets, and queries DNSBL zones.
    """
    findings = []
    
    # 1. Resolve domain to IPv4
    try:
        ip = socket.gethostbyname(hostname)
    except Exception as e:
        return {
            "score_percentage": 100,
            "ip": None,
            "listed_on": [],
            "findings": [{
                "key": "reputation_dns_err",
                "title": "Résolution IP indisponible pour le contrôle de réputation",
                "category": "DNS & Email",
                "status": "info",
                "severity": "info",
                "score_weight": 0,
                "earned_score": 0,
                "message": f"Impossible de résoudre l'adresse IP de {hostname}.",
                "remediation_key": "dns_spf"
            }]
        }

    parts = ip.split(".")
    if len(parts) != 4:
        return {"score_percentage": 100, "ip": ip, "listed_on": [], "findings": []}

    rev_ip = ".".join(reversed(parts))
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    listed_on = []

    for bl in DNSBL_SERVERS:
        query_domain = f"{rev_ip}.{bl['zone']}"
        try:
            answers = resolver.resolve(query_domain, "A")
            if answers:
                listed_on.append(bl["name"])
        except Exception:
            # NXDOMAIN or timeout means clean/not listed
            pass

    if listed_on:
        findings.append({
            "key": "ip_blacklisted",
            "title": f"ALERTE : IP ({ip}) inscrite sur liste noire anti-spam !",
            "category": "DNS & Email",
            "status": "fail",
            "severity": "critical",
            "score_weight": 20,
            "earned_score": 0,
            "value": f"Listes noires : {', '.join(listed_on)} (IP : {ip})",
            "message": f"L'adresse IP du serveur ({ip}) est fichée sur {len(listed_on)} liste(s) noire(s) ({', '.join(listed_on)}). Risque massif : tous les emails envoyés par ce domaine peuvent être rejetés ou placés en spam.",
            "remediation_key": "delist_ip_blacklist"
        })
        score_pct = 0
    else:
        findings.append({
            "key": "ip_clean_reputation",
            "title": f"Réputation IP irréprochable ({ip})",
            "category": "DNS & Email",
            "status": "pass",
            "severity": "info",
            "score_weight": 10,
            "earned_score": 10,
            "value": f"IP inspectée : {ip}",
            "message": "L'adresse IP du serveur n'est répertoriée sur aucune liste noire mondiale (Spamhaus, SpamCop, Barracuda). Excellente délivrabilité d'e-mails.",
            "remediation_key": "delist_ip_blacklist"
        })
        score_pct = 100

    return {
        "score_percentage": score_pct,
        "ip": ip,
        "listed_on": listed_on,
        "findings": findings
    }

