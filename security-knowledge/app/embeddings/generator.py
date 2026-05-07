import asyncio
import httpx
from app.config import settings
import structlog

logger = structlog.get_logger(__name__)


async def generate_embedding(text: str) -> list[float]:
    if not settings.EMBEDDING_API_URL:
        # Return zero vector as fallback
        return [0.0] * settings.EMBEDDING_DIM
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{settings.EMBEDDING_API_URL}/embeddings",
            json={"input": text, "model": settings.EMBEDDING_MODEL},
            headers={"Authorization": f"Bearer {settings.EMBEDDING_API_KEY}"},
        )
        resp.raise_for_status()
        data = resp.json()
        return data["data"][0]["embedding"]


async def generate_embeddings_batch(texts: list[str]) -> list[list[float]]:
    tasks = [generate_embedding(t) for t in texts]
    return await asyncio.gather(*tasks)
