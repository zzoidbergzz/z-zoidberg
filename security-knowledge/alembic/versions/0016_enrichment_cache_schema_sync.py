"""Sync enrichment_cache schema with current SQLAlchemy model.

The original 0007 migration used a different column layout
(populated_by_tenant_id, entity_value_hash, no tenant_id, no success,
no created_at/updated_at).  The model was later updated to use a simpler,
tenant-scoped shape.  This migration adds the missing columns so the ORM
can query without UndefinedColumnError.

Revision ID: 0016
Revises: 0015
Create Date: 2026-05-08
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Add tenant_id — backfill from populated_by_tenant_id
    op.add_column(
        "enrichment_cache",
        sa.Column("tenant_id", UUID(as_uuid=True), nullable=True),
    )
    op.execute(
        "UPDATE enrichment_cache SET tenant_id = populated_by_tenant_id "
        "WHERE populated_by_tenant_id IS NOT NULL"
    )
    # Leave nullable=True so rows without a tenant don't break the migration.
    # The service always passes a tenant_id for new inserts.
    op.create_index("ix_enrichment_cache_tenant_id", "enrichment_cache", ["tenant_id"])

    # 2. Add success boolean
    op.add_column(
        "enrichment_cache",
        sa.Column("success", sa.Boolean(), nullable=False, server_default="true"),
    )

    # 3. Add TimestampMixin columns
    op.add_column(
        "enrichment_cache",
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.add_column(
        "enrichment_cache",
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    # Back-fill created_at from fetched_at where available
    op.execute(
        "UPDATE enrichment_cache SET created_at = fetched_at, updated_at = fetched_at "
        "WHERE fetched_at IS NOT NULL"
    )


def downgrade() -> None:
    op.drop_index("ix_enrichment_cache_tenant_id", "enrichment_cache")
    op.drop_column("enrichment_cache", "tenant_id")
    op.drop_column("enrichment_cache", "success")
    op.drop_column("enrichment_cache", "created_at")
    op.drop_column("enrichment_cache", "updated_at")
