"""
Audite Database & Storage Engine (SQLite).
Persists audit reports, provides permalinks, and retrieves recent scan feeds and history.
"""

import os
import json
import uuid
import sqlite3
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

DB_PATH = os.path.join(os.path.dirname(__file__), "audite.db")


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes tables and indexes."""
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audits (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                url TEXT NOT NULL,
                global_score INTEGER NOT NULL,
                grade TEXT NOT NULL,
                grade_label TEXT NOT NULL,
                grade_color TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                report_json TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS monitored_domains (
                id TEXT PRIMARY KEY,
                domain TEXT UNIQUE NOT NULL,
                url TEXT NOT NULL,
                webhook_url TEXT,
                latest_score INTEGER DEFAULT 0,
                latest_grade TEXT DEFAULT 'N/A',
                ssl_expires_in_days INTEGER,
                ssl_issuer TEXT,
                alert_status TEXT DEFAULT 'ok',
                last_checked_at TIMESTAMP,
                created_at TIMESTAMP NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS leads (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                domain TEXT NOT NULL,
                audit_id TEXT,
                global_score INTEGER DEFAULT 0,
                grade TEXT DEFAULT 'N/A',
                critical_count INTEGER DEFAULT 0,
                notes TEXT,
                created_at TIMESTAMP NOT NULL
            );
        """)
        # Safe migration if column doesn't exist
        try:
            conn.execute("ALTER TABLE monitored_domains ADD COLUMN webhook_url TEXT;")
        except Exception:
            pass
        for col, col_type in [("audit_id", "TEXT"), ("global_score", "INTEGER DEFAULT 0"), ("critical_count", "INTEGER DEFAULT 0"), ("notes", "TEXT")]:
            try:
                conn.execute(f"ALTER TABLE leads ADD COLUMN {col} {col_type};")
            except Exception:
                pass
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audits_domain ON audits(domain);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audits_created ON audits(created_at DESC);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_monitored_domain ON monitored_domains(domain);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_leads_created ON leads(created_at DESC);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_leads_email ON leads(email);")
        conn.commit()


def save_audit(report: Dict[str, Any]) -> str:
    """Saves an audit report and returns unique audit ID."""
    init_db()
    audit_id = f"aud_{uuid.uuid4().hex[:12]}"
    created_at = datetime.now(timezone.utc).isoformat()
    
    # Extract domain from target url
    domain = report.get("domain") or report.get("url", "").replace("https://", "").replace("http://", "").split("/")[0]
    
    report["audit_id"] = audit_id
    report["created_at"] = created_at
    report["domain"] = domain

    with get_db_connection() as conn:
        conn.execute("""
            INSERT INTO audits (
                id, domain, url, global_score, grade, grade_label, grade_color, summary_json, report_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            audit_id,
            domain,
            report.get("url", ""),
            report.get("global_score", 0),
            report.get("grade", "C"),
            report.get("grade_label", "Moyen"),
            report.get("grade_color", "amber"),
            json.dumps(report.get("summary", {})),
            json.dumps(report),
            created_at
        ))
        conn.commit()

    return audit_id


def get_audit_by_id(audit_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full audit report by ID."""
    init_db()
    with get_db_connection() as conn:
        row = conn.execute("SELECT report_json FROM audits WHERE id = ?", (audit_id,)).fetchone()
        if row:
            return json.loads(row["report_json"])
    return None


def get_latest_audit_by_domain(domain: str) -> Optional[Dict[str, Any]]:
    """Retrieves latest audit report by domain name."""
    init_db()
    clean_domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT report_json FROM audits WHERE domain = ? ORDER BY created_at DESC LIMIT 1",
            (clean_domain,)
        ).fetchone()
        if row:
            return json.loads(row["report_json"])
    return None


def get_recent_audits(limit: int = 8) -> List[Dict[str, Any]]:
    """Retrieves recent audit summaries for homepage feed."""
    init_db()
    with get_db_connection() as conn:
        rows = conn.execute("""
            SELECT id, domain, url, global_score, grade, grade_label, grade_color, summary_json, created_at
            FROM audits
            ORDER BY created_at DESC
            LIMIT ?
        """, (limit,)).fetchall()
        
        results = []
        for r in rows:
            results.append({
                "id": r["id"],
                "domain": r["domain"],
                "url": r["url"],
                "global_score": r["global_score"],
                "grade": r["grade"],
                "grade_label": r["grade_label"],
                "grade_color": r["grade_color"],
                "summary": json.loads(r["summary_json"]),
                "created_at": r["created_at"]
            })
        return results


def get_domain_history(domain: str, limit: int = 5) -> List[Dict[str, Any]]:
    """Retrieves score history for a specific domain to track progression."""
    init_db()
    clean_domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
    with get_db_connection() as conn:
        rows = conn.execute("""
            SELECT id, global_score, grade, created_at
            FROM audits
            WHERE domain = ?
            ORDER BY created_at DESC
            LIMIT ?
        """, (clean_domain, limit)).fetchall()
        
        return [{
            "id": r["id"],
            "global_score": r["global_score"],
            "grade": r["grade"],
            "created_at": r["created_at"]
        } for r in rows]


def add_monitored_domain(domain: str, url: str, webhook_url: Optional[str] = None) -> Dict[str, Any]:
    """Adds a domain to active monitoring list."""
    init_db()
    clean_domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
    clean_url = url if url.startswith("http") else f"https://{clean_domain}"
    monitor_id = f"mon_{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()
    
    with get_db_connection() as conn:
        conn.execute("""
            INSERT INTO monitored_domains (id, domain, url, webhook_url, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET 
                url = excluded.url,
                webhook_url = COALESCE(excluded.webhook_url, monitored_domains.webhook_url)
        """, (monitor_id, clean_domain, clean_url, webhook_url, now))
        conn.commit()
    
    # Pre-populate with latest audit if available
    latest = get_latest_audit_by_domain(clean_domain)
    if latest:
        ssl_info = latest.get("pillars", {}).get("ssl", {})
        update_monitored_domain_status(
            domain=clean_domain,
            score=latest.get("global_score", 0),
            grade=latest.get("grade", "C"),
            ssl_days=ssl_info.get("expires_in_days"),
            ssl_issuer=ssl_info.get("issuer")
        )
    return {"id": monitor_id, "domain": clean_domain, "url": clean_url, "webhook_url": webhook_url}


def update_monitored_webhook(domain: str, webhook_url: str) -> bool:
    """Updates or sets webhook URL for a monitored domain."""
    init_db()
    clean_domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
    with get_db_connection() as conn:
        cursor = conn.execute("UPDATE monitored_domains SET webhook_url = ? WHERE domain = ?", (webhook_url, clean_domain))
        conn.commit()
        return cursor.rowcount > 0


def get_all_monitored_domains() -> List[Dict[str, Any]]:
    """Retrieves all monitored domains with their health status."""
    init_db()
    with get_db_connection() as conn:
        rows = conn.execute("""
            SELECT id, domain, url, webhook_url, latest_score, latest_grade, ssl_expires_in_days, ssl_issuer, alert_status, last_checked_at, created_at
            FROM monitored_domains
            ORDER BY created_at DESC
        """).fetchall()
        
        return [dict(r) for r in rows]


def delete_monitored_domain(domain_or_id: str) -> bool:
    """Removes a domain from monitoring."""
    init_db()
    clean = domain_or_id.lower().replace("https://", "").replace("http://", "").split("/")[0]
    with get_db_connection() as conn:
        cursor = conn.execute("DELETE FROM monitored_domains WHERE id = ? OR domain = ?", (domain_or_id, clean))
        conn.commit()
        return cursor.rowcount > 0


def update_monitored_domain_status(domain: str, score: int, grade: str, ssl_days: Optional[int], ssl_issuer: Optional[str]):
    """Updates monitoring metrics after a scan."""
    init_db()
    clean_domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
    now = datetime.now(timezone.utc).isoformat()
    
    # Calculate alert level
    alert_status = "ok"
    if ssl_days is not None and ssl_days <= 7:
        alert_status = "critical"
    elif ssl_days is not None and ssl_days <= 20:
        alert_status = "warning"
    elif score < 50:
        alert_status = "critical"
    elif score < 70:
        alert_status = "warning"
        
    with get_db_connection() as conn:
        conn.execute("""
            UPDATE monitored_domains
            SET latest_score = ?,
                latest_grade = ?,
                ssl_expires_in_days = ?,
                ssl_issuer = ?,
                alert_status = ?,
                last_checked_at = ?
            WHERE domain = ?
        """, (score, grade, ssl_days, ssl_issuer, alert_status, now, clean_domain))
        conn.commit()


def save_lead(email: str, domain: str, audit_id: Optional[str] = None, global_score: int = 0, grade: str = "N/A", critical_count: int = 0, notes: str = "") -> Dict[str, Any]:
    """Stores a prospect captured via the lead magnet."""
    init_db()
    lead_id = f"lead_{uuid.uuid4().hex[:10]}"
    clean_domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
    created_at = datetime.now(timezone.utc).isoformat()
    
    with get_db_connection() as conn:
        conn.execute("""
            INSERT INTO leads (id, email, domain, audit_id, global_score, grade, critical_count, notes, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (lead_id, email.strip().lower(), clean_domain, audit_id, global_score, grade, critical_count, notes, created_at))
        conn.commit()
        
    return {
        "id": lead_id,
        "email": email.strip().lower(),
        "domain": clean_domain,
        "audit_id": audit_id,
        "global_score": global_score,
        "grade": grade,
        "critical_count": critical_count,
        "created_at": created_at
    }


def get_all_leads() -> List[Dict[str, Any]]:
    """Returns all captured prospect leads sorted by date."""
    init_db()
    with get_db_connection() as conn:
        rows = conn.execute("""
            SELECT id, email, domain, audit_id, global_score, grade, critical_count, notes, created_at
            FROM leads
            ORDER BY created_at DESC
        """).fetchall()
        return [dict(r) for r in rows]


def delete_lead(lead_id: str) -> bool:
    """Removes a lead by ID."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.execute("DELETE FROM leads WHERE id = ?", (lead_id,))
        conn.commit()
        return cursor.rowcount > 0


