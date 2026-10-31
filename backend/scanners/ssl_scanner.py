"""
SSL/TLS Security Scanner.
Connects via TLS socket to analyze certificate validity, protocol versions, and cipher suites.
"""

import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, Optional


def parse_ssl_date(date_str: str) -> Optional[datetime]:
    """Parses standard ASN1 date format returned by Python SSL module."""
    try:
        # Example: 'May 15 12:00:00 2026 GMT'
        return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def scan_ssl_tls(hostname: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Performs SSL/TLS handshake and inspects certificate, protocol version, and ciphers.
    Includes automatic retry with extended timeout for high-latency CDNs.
    """
    findings = []
    
    context = ssl.create_default_context()
    cert = None
    version = None
    cipher = None
    last_err = None

    # Try connection (up to 2 attempts for resilient handling of high-latency CDNs)
    for attempt in range(2):
        try:
            current_timeout = timeout if attempt == 0 else 3.0
            with socket.create_connection((hostname, port), timeout=current_timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    cipher = ssock.cipher()
                    break
        except ssl.SSLCertVerificationError as e:
            return {
                "status": "fail",
                "score_percentage": 0,
                "error": f"Erreur de validation du certificat SSL : {str(e.verify_message if hasattr(e, 'verify_message') else e)}",
                "findings": [{
                    "key": "ssl_invalid",
                    "title": "Certificat SSL Invalide ou Auto-signé",
                    "status": "fail",
                    "severity": "critical",
                    "score_weight": 35,
                    "earned_score": 0,
                    "message": f"Le certificat SSL du serveur est rejeté par les navigateurs : {str(e)}",
                    "remediation_key": "ssl_certificate"
                }]
            }
        except (socket.timeout, TimeoutError) as e:
            last_err = e
            continue
        except Exception as e:
            last_err = e
            if "timed out" in str(e).lower():
                continue
            break

    if not cert:
        is_timeout = isinstance(last_err, (socket.timeout, TimeoutError)) or (last_err and "timed out" in str(last_err).lower())
        title = "Délai de négociation SSL/TLS dépassé" if is_timeout else "Pas de support HTTPS / SSL sur ce port"
        msg = f"Le serveur a mis trop de temps à répondre au protocole HTTPS (latence réseau ou CDN surchargé) : {str(last_err)}" if is_timeout else f"Le serveur n'a pas répondu au protocole HTTPS : {str(last_err)}"
        
        return {
            "status": "fail",
            "score_percentage": 0,
            "error": f"Impossible d'établir une connexion SSL/TLS sur le port {port} : {str(last_err)}",
            "findings": [{
                "key": "ssl_missing",
                "title": title,
                "status": "fail",
                "severity": "critical",
                "score_weight": 35,
                "earned_score": 0,
                "message": msg,
                "remediation_key": "ssl_certificate"
            }]
        }

    # Extract Certificate Info
    subject_dict = dict(x[0] for x in cert.get("subject", ()))
    issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
    
    common_name = subject_dict.get("commonName", hostname)
    issuer_org = issuer_dict.get("organizationName") or issuer_dict.get("commonName", "Inconnue")
    
    san_list = [entry[1] for entry in cert.get("subjectAltName", ()) if entry[0] == "DNS"]
    
    not_after_str = cert.get("notAfter")
    not_before_str = cert.get("notBefore")
    expire_date = parse_ssl_date(not_after_str) if not_after_str else None
    
    now = datetime.now(timezone.utc)
    days_left = (expire_date - now).days if expire_date else 0
    is_expired = days_left < 0

    # 1. Certificate Validity Check
    if is_expired:
        findings.append({
            "key": "cert_expired",
            "title": "Certificat SSL Expiré",
            "status": "fail",
            "severity": "critical",
            "score_weight": 20,
            "earned_score": 0,
            "message": f"Le certificat a expiré il y a {abs(days_left)} jour(s). Les navigateurs bloquent l'accès aux utilisateurs.",
            "remediation_key": "ssl_certificate"
        })
    elif days_left < 15:
        findings.append({
            "key": "cert_expiring_soon",
            "title": "Certificat SSL expirant très prochainement",
            "status": "warning",
            "severity": "high",
            "score_weight": 20,
            "earned_score": 10,
            "message": f"Le certificat expire dans {days_left} jour(s). Le renouvellement doit être effectué rapidement.",
            "remediation_key": "ssl_certificate"
        })
    else:
        findings.append({
            "key": "cert_valid",
            "title": "Certificat SSL valide et certifié",
            "status": "pass",
            "severity": "info",
            "score_weight": 20,
            "earned_score": 20,
            "message": f"Certificat valide délivré par {issuer_org}. Expire dans {days_left} jours.",
            "remediation_key": "ssl_certificate"
        })

    # 2. TLS Protocol Version Check
    protocol_score = 0
    if version in ["TLSv1.3", "TLSv1.2"]:
        protocol_score = 15
        findings.append({
            "key": "tls_version",
            "title": f"Protocole Moderne : {version}",
            "status": "pass",
            "severity": "info",
            "score_weight": 15,
            "earned_score": 15,
            "message": f"Le serveur négocie {version}, conforme aux recommandations de l'ANSSI et du NIST.",
            "remediation_key": "ssl_protocols"
        })
    else:
        findings.append({
            "key": "tls_version",
            "title": f"Protocole Obsolète : {version}",
            "status": "fail",
            "severity": "critical",
            "score_weight": 15,
            "earned_score": 0,
            "message": f"La version de protocole négociée ({version}) est vulnérable (POODLE, BEAST, etc.). Désactivez SSLv3, TLS 1.0 et TLS 1.1.",
            "remediation_key": "ssl_protocols"
        })

    # 3. Cipher Suite & Key Length Check
    cipher_name, cipher_proto, cipher_bits = cipher if cipher else ("Inconnu", "Inconnu", 0)
    if cipher_bits >= 128:
        findings.append({
            "key": "tls_cipher",
            "title": f"Suite Cryptographique Robuste ({cipher_bits} bits)",
            "status": "pass",
            "severity": "info",
            "score_weight": 10,
            "earned_score": 10,
            "message": f"Algorithme négocié : {cipher_name} ({cipher_bits} bits).",
            "remediation_key": "ssl_protocols"
        })
    else:
        findings.append({
            "key": "tls_cipher",
            "title": "Chiffrement SSL faible",
            "status": "fail",
            "severity": "high",
            "score_weight": 10,
            "earned_score": 0,
            "message": f"La clé de chiffrement ({cipher_bits} bits) est inférieure au standard minimal de 128 bits.",
            "remediation_key": "ssl_protocols"
        })

    total_earned = sum(f["earned_score"] for f in findings)
    max_possible = sum(f["score_weight"] for f in findings)
    percentage = round((total_earned / max_possible) * 100) if max_possible > 0 else 0

    return {
        "status": "pass",
        "score_percentage": percentage,
        "hostname": hostname,
        "common_name": common_name,
        "issuer": issuer_org,
        "expires_in_days": days_left,
        "expiration_date": expire_date.strftime("%Y-%m-%d %H:%M:%S UTC") if expire_date else None,
        "protocol": version,
        "cipher": {
            "name": cipher_name,
            "bits": cipher_bits
        },
        "san_count": len(san_list),
        "sans": san_list[:10],
        "findings": findings
    }
