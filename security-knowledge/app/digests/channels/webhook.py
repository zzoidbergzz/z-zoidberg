import httpx
import structlog
logger = structlog.get_logger(__name__)

async def send_webhook_digest(url: str, payload: dict) -> bool:
    if not url:
        return False
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json=payload)
            return resp.status_code < 400
    except Exception as exc:
        logger.warning("webhook_digest_failed", error=str(exc))
        return False
