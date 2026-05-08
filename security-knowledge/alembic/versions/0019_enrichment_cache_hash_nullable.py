"""Make enrichment_cache.entity_value_hash nullable.

The current SQLAlchemy model does not include entity_value_hash; the column
was part of the original schema but is no longer used.  Making it nullable
lets the ORM insert rows without providing it.

Revision ID: 0019
Revises: 0018
Create Date: 2026-05-08
"""
from alembic import op
import sqlalchemy as sa

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("enrichment_cache", "entity_value_hash", nullable=True, existing_type=sa.String(64))


def downgrade() -> None:
    # Re-nullify any NULLs before reverting (best effort)
    op.execute("UPDATE enrichment_cache SET entity_value_hash = encode(sha256(entity_value::bytea), 'hex') WHERE entity_value_hash IS NULL")
    op.alter_column("enrichment_cache", "entity_value_hash", nullable=False, existing_type=sa.String(64))
