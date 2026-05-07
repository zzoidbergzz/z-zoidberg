import httpx
import structlog
logger = structlog.get_logger(__name__)

async def send_slack_digest(webhook_url: str, text: str) -> bool:
    if not webhook_url:
        return False
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json={"text": text})
            return resp.status_code == 200
    except Exception as exc:
        logger.warning("slack_digest_failed", error=str(exc))
        return False
