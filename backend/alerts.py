"""
Security Alert & Notification Dispatcher.
Dispatches real-time security alerts to Discord, Slack, and generic webhooks when:
- An SSL certificate is nearing expiration (e.g. <= 7 days).
- A severe security score regression is detected.
- A critical secret leak is found during an audit.
"""

from typing import Optional, Dict, Any
from datetime import datetime, timezone
import httpx


async def send_security_alert(
    domain: str,
    event_type: str,
    title: str,
    message: str,
    score: int,
    grade: str,
    webhook_url: str,
    days_left: Optional[int] = None
) -> bool:
    """
    Sends structured alert embed to Discord, Slack or generic webhook endpoint.
    """
    if not webhook_url or not webhook_url.startswith("http"):
        return False

    is_discord = "discord.com/api/webhooks" in webhook_url or "discordapp.com" in webhook_url
    is_slack = "hooks.slack.com" in webhook_url

    color = 0xef4444 if score < 60 or (days_left is not None and days_left <= 7) else 0xf59e0b

    payload: Dict[str, Any] = {}

    if is_discord:
        embed = {
            "title": f"🚨 {title}",
            "description": message,
            "color": color,
            "fields": [
                {"name": "🌐 Domaine", "value": f"`{domain}`", "inline": True},
                {"name": "📊 Score & Note", "value": f"**{score}/100** ({grade})", "inline": True},
            ],
            "footer": {
                "text": "Audite Security Engine • Alerte Proactive",
                "icon_url": "https://img.icons8.com/color/48/000000/shield.png"
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        if days_left is not None:
            embed["fields"].append({"name": "⏳ Expiration SSL", "value": f"**{days_left} jour(s) restant(s)**", "inline": True})
        
        payload = {
            "username": "Audite Security Bot",
            "avatar_url": "https://img.icons8.com/color/96/shield.png",
            "embeds": [embed]
        }

    elif is_slack:
        fields = [
            f"*Domaine :* `{domain}`",
            f"*Score Actuel :* *{score}/100* ({grade})"
        ]
        if days_left is not None:
            fields.append(f"*Expiration SSL :* *{days_left} jours*")

        payload = {
            "text": f"🚨 *{title}* sur `{domain}`",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"🚨 *{title}*\n{message}\n\n" + " • ".join(fields)
                    }
                }
            ]
        }
    else:
        # Generic JSON Webhook
        payload = {
            "service": "audite-security",
            "event": event_type,
            "domain": domain,
            "title": title,
            "message": message,
            "score": score,
            "grade": grade,
            "ssl_days_left": days_left,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.post(webhook_url, json=payload)
            return resp.status_code in [200, 204]
    except Exception:
        return False


async def send_test_webhook(webhook_url: str) -> bool:
    """Sends a friendly verification test notification to confirm webhook integration."""
    return await send_security_alert(
        domain="audite.test",
        event_type="test_ping",
        title="Connexion Réussie au Système d'Alerte Audite !",
        message="Félicitations, vos alertes de sécurité sont désormais configurées. Vous recevrez des notifications automatiques dès qu'une anomalie critique ou une expiration SSL est détectée.",
        score=95,
        grade="A+",
        webhook_url=webhook_url,
        days_left=88
    )

