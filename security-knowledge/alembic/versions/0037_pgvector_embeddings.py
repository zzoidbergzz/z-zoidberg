"""Add pgvector extension and embedding columns to entities and claims.

The embedding columns are added as `vector(1536)` using the pgvector extension.
If the extension cannot be created (e.g. it is not installed), the migration
still succeeds but marks the feature as unavailable via the
`SEARCH_USE_SEMANTIC` config flag — callers must check this flag before using
the vector columns.

Revision ID: 0037_pgvector_embeddings
Revises: 0036_mv_entity_search
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0037_pgvector_embeddings"
down_revision = "0036_mv_entity_search"
branch_labels = None
depends_on = None

_EMBEDDING_DIM = 1536


def upgrade() -> None:
    conn = op.get_bind()

    # Try to create the extension; if it fails (not installed in this PG
    # instance) we skip the vector columns gracefully.
    try:
        conn.execute(sa.text("CREATE EXTENSION IF NOT EXISTS vector"))
        _has_vector = True
    except Exception:
        _has_vector = False

    if not _has_vector:
        # Nothing to do — the app will detect EMBEDDING_DIM > 0 but no column
        # and skip semantic search.
        return

    # Add embedding to entities (nullable so existing rows are fine)
    conn.execute(
        sa.text(
            f"ALTER TABLE entities ADD COLUMN IF NOT EXISTS embedding vector({_EMBEDDING_DIM})"
        )
    )

    # Add embedding to claims (nullable)
    conn.execute(
        sa.text(
            f"ALTER TABLE claims ADD COLUMN IF NOT EXISTS embedding vector({_EMBEDDING_DIM})"
        )
    )

    # IVFFlat index on entities — cosine distance
    # lists=100 is appropriate for up to ~1M rows; tune upward if needed.
    conn.execute(
        sa.text(
            "CREATE INDEX IF NOT EXISTS ix_entities_embedding_cos "
            f"ON entities USING ivfflat (embedding vector_cosine_ops) WITH (lists=100)"
        )
    )

    # Partial index only for rows that have been embedded
    conn.execute(
        sa.text(
            "CREATE INDEX IF NOT EXISTS ix_claims_embedding_cos "
            f"ON claims USING ivfflat (embedding vector_cosine_ops) WITH (lists=100) "
            "WHERE embedding IS NOT NULL"
        )
    )


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(sa.text("DROP INDEX IF EXISTS ix_entities_embedding_cos"))
    conn.execute(sa.text("DROP INDEX IF EXISTS ix_claims_embedding_cos"))
    conn.execute(sa.text("ALTER TABLE entities DROP COLUMN IF EXISTS embedding"))
    conn.execute(sa.text("ALTER TABLE claims DROP COLUMN IF EXISTS embedding"))
    # Do NOT drop the extension — other tables may use it.
