"""Enable pg_stat_statements extension.

Revision ID: 0038_pg_stat_statements
Revises: 0037_pgvector_embeddings
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0038_pg_stat_statements"
down_revision = "0037_pgvector_embeddings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(sa.text("CREATE EXTENSION IF NOT EXISTS pg_stat_statements"))


def downgrade() -> None:
    # Keep extension installed because other operational tooling may depend on it.
    pass
