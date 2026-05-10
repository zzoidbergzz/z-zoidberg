"""ARQ job: generate and store pgvector embeddings for entities and claims.

Enqueued by the ingest worker after every entity/claim create or update.
Jobs are idempotent — re-running overwrites with the latest embedding.
"""
from __future__ import annotations

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from app.config import settings
from app.embeddings.generator import generate_embedding

logger = structlog.get_logger(__name__)

_SUPPORTED_TABLES = {"entities", "claims"}


async def generate_embedding_for_row(
    ctx: dict,
    *,
    table: str,
    row_id: str,
) -> None:
    """ARQ job: embed a single entity or claim row and write the vector back.

    Args:
        table:  Either "entities" or "claims".
        row_id: UUID of the row to embed (string form).
    """
    if table not in _SUPPORTED_TABLES:
        logger.warning("embedding_unknown_table", table=table)
        return

    if not settings.SEARCH_USE_SEMANTIC or not settings.EMBEDDING_API_URL:
        # Semantic search not enabled — skip silently.
        return

    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    try:
        async with factory() as session:
            if table == "entities":
                row = await session.execute(
                    text(
                        "SELECT kind, canonical_name FROM entities WHERE id = :id"
                    ),
                    {"id": row_id},
                )
                record = row.fetchone()
                if record is None:
                    return
                text_to_embed = f"{record.kind}: {record.canonical_name}"
            else:  # claims
                row = await session.execute(
                    text(
                        "SELECT claim_type, description FROM claims WHERE id = :id"
                    ),
                    {"id": row_id},
                )
                record = row.fetchone()
                if record is None:
                    return
                text_to_embed = f"{record.claim_type}: {record.description or ''}"

            embedding = await generate_embedding(text_to_embed)
            if not embedding or all(v == 0.0 for v in embedding):
                # Zero vector from disabled provider — don't overwrite real embeddings.
                return

            await session.execute(
                text(
                    f"UPDATE {table} SET embedding = :emb WHERE id = :id"
                ),
                {"emb": str(embedding), "id": row_id},
            )
            await session.commit()
            logger.info("embedding_stored", table=table, row_id=row_id)
    except Exception as exc:
        logger.error("embedding_job_failed", table=table, row_id=row_id, error=str(exc))
    finally:
        await engine.dispose()
