"""
Audite Security Engine - Notification Manager
Envoie des alertes instantanées par email à l'administrateur (kpakpovictor12@gmail.com)
dès qu'un nouveau prospect demande son rapport certifié.
"""

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any
import httpx

ADMIN_NOTIFICATION_EMAIL = os.getenv("ADMIN_EMAIL", "kpakpovictor12@gmail.com")
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")


async def notify_new_lead(lead_data: Dict[str, Any]) -> bool:
    """
    Envoie une alerte immédiate à l'administrateur lors de la capture d'un lead.
    """
    domain = lead_data.get("domain", "domaine-inconnu")
    prospect_email = lead_data.get("email", "inconnu")
    score = lead_data.get("global_score", 0)
    grade = lead_data.get("grade", "N/A")
    critical_count = lead_data.get("critical_count", 0)

    subject = f"🔔 [Audite] Nouveau Prospect : {domain} (Note {grade} - {score}/100)"
    
    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #0f172a; color: #f8fafc; padding: 24px; border-radius: 12px; border: 1px solid #334155;">
        <h2 style="color: #10b981; margin-top: 0;">🎯 Nouveau Prospect Capturé sur Audite !</h2>
        <p style="color: #cbd5e1; font-size: 14px;">Un visiteur vient de demander un audit officiel certifié pour son site web :</p>
        
        <table style="width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 14px;">
            <tr style="border-bottom: 1px solid #334155;">
                <td style="padding: 10px; color: #94a3b8; font-weight: bold;">Email du Prospect :</td>
                <td style="padding: 10px; color: #38bdf8; font-weight: bold;"><a href="mailto:{prospect_email}" style="color: #38bdf8; text-decoration: underline;">{prospect_email}</a></td>
            </tr>
            <tr style="border-bottom: 1px solid #334155;">
                <td style="padding: 10px; color: #94a3b8; font-weight: bold;">Site Audité :</td>
                <td style="padding: 10px; color: #f8fafc; font-weight: bold;">{domain}</td>
            </tr>
            <tr style="border-bottom: 1px solid #334155;">
                <td style="padding: 10px; color: #94a3b8; font-weight: bold;">Score de Sécurité :</td>
                <td style="padding: 10px; color: #f59e0b; font-weight: bold;">{score}/100 (Note {grade})</td>
            </tr>
            <tr style="border-bottom: 1px solid #334155;">
                <td style="padding: 10px; color: #94a3b8; font-weight: bold;">Failles Critiques :</td>
                <td style="padding: 10px; color: {'#ef4444' if critical_count > 0 else '#10b981'}; font-weight: bold;">{critical_count} critique(s)</td>
            </tr>
        </table>
        
        <div style="background: #1e293b; padding: 14px; border-radius: 8px; font-size: 13px; color: #cbd5e1; margin-bottom: 20px;">
            💡 <strong>Action Recommandée :</strong> Ce prospect s'inquiète de la sécurité de son site. Réponds-lui dans les 30 minutes avec le <em>Modèle 1 (Audit Gracieux)</em> ou propose-lui la prestation corrective clé-en-main !
        </div>
        
        <p style="font-size: 11px; color: #64748b; margin-bottom: 0;">Alerte automatique générée par votre plateforme Audite Cloud • https://audite-232m.onrender.com</p>
    </div>
    """

    # 1. Méthode Resend API (si clé configurée)
    if RESEND_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                res = await client.post(
                    "https://api.resend.com/emails",
                    headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
                    json={
                        "from": "Audite Alerts <onboarding@resend.dev>",
                        "to": [ADMIN_NOTIFICATION_EMAIL],
                        "subject": subject,
                        "html": html_content
                    }
                )
                if res.status_code in [200, 201]:
                    print(f"[Notifier] Email envoyé avec succès via Resend à {ADMIN_NOTIFICATION_EMAIL}")
                    return True
        except Exception as e:
            print(f"[Notifier] Erreur Resend: {e}")

    # 2. Méthode SMTP direct (si SMTP configuré)
    if SMTP_HOST and SMTP_USER and SMTP_PASS:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = SMTP_USER
            msg["To"] = ADMIN_NOTIFICATION_EMAIL
            msg.attach(MIMEText(html_content, "html"))

            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=6.0) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)
                server.sendmail(SMTP_USER, [ADMIN_NOTIFICATION_EMAIL], msg.as_string())
            print(f"[Notifier] Email envoyé avec succès via SMTP à {ADMIN_NOTIFICATION_EMAIL}")
            return True
        except Exception as e:
            print(f"[Notifier] Erreur SMTP: {e}")

    # 3. Log clair dans la console (accessible dans les logs Render 24h/24)
    print(f"\n=======================================================")
    print(f"[NOUVEAU PROSPECT] Destinataire: {ADMIN_NOTIFICATION_EMAIL}")
    print(f"Domaine: {domain} | Email: {prospect_email} | Score: {score}/100 ({grade}) | Critiques: {critical_count}")
    print(f"=======================================================\n")
    return True
