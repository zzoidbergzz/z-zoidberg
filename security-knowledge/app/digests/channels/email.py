import structlog
logger = structlog.get_logger(__name__)

async def send_email_digest(to: str, subject: str, html_body: str) -> bool:
    logger.info("email_digest_stub", to=to, subject=subject)
    return True
