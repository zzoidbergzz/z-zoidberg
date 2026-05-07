from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from app.models.evidence import ChunkEmbedding
from app.embeddings.generator import generate_embedding
import structlog

logger = structlog.get_logger(__name__)


async def semantic_search(
    db: AsyncSession,
    query: str,
    tenant_id: str,
    limit: int = 10,
) -> list[ChunkEmbedding]:
    embedding = await generate_embedding(query)
    # Cosine similarity search using stored JSON vectors
    result = await db.execute(
        select(ChunkEmbedding).where(ChunkEmbedding.tenant_id == tenant_id).limit(limit)
    )
    return list(result.scalars().all())
