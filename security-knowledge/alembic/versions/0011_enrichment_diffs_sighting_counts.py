"""Enrichment diffs, sighting counts, sector fields on pingback, business_sector on users

Revision ID: 0011
Revises: 0010
Create Date: 2026-05-07
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add business_sector to users
    op.add_column("users", sa.Column("business_sector", sa.String(100), nullable=False, server_default="UK-General"))

    # Add sighting_count / last_sighted_at / sector_context to ioc_watches
    op.add_column("ioc_watches", sa.Column("sighting_count", sa.Integer, nullable=False, server_default="0"))
    op.add_column("ioc_watches", sa.Column("last_sighted_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("ioc_watches", sa.Column("sector_context", sa.String(100), nullable=True))

    # Add seeker_sector / sector_share / seeker_comment to ioc_sightings
    op.add_column("ioc_sightings", sa.Column("seeker_sector", sa.String(100), nullable=True))
    op.add_column("ioc_sightings", sa.Column("sector_share", sa.String(10), nullable=False, server_default="limited"))
    op.add_column("ioc_sightings", sa.Column("seeker_comment", sa.Text, nullable=True))

    # Create enrichment_diffs table
    op.create_table(
        "enrichment_diffs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("cache_entry_id", UUID(as_uuid=True), sa.ForeignKey("enrichment_cache.id", ondelete="SET NULL"), nullable=True),
        sa.Column("provider", sa.String(100), nullable=False),
        sa.Column("entity_kind", sa.String(100), nullable=False),
        sa.Column("entity_value", sa.String(512), nullable=False),
        sa.Column("previous_normalized", JSONB, nullable=False, server_default="{}"),
        sa.Column("new_normalized", JSONB, nullable=False, server_default="{}"),
        sa.Column("diff_summary", JSONB, nullable=False, server_default="{}"),
        sa.Column("has_changes", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("requested_by_user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("requested_by_tenant_id", UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_enrichment_diffs_provider", "enrichment_diffs", ["provider"])
    op.create_index("ix_enrichment_diffs_entity_value", "enrichment_diffs", ["entity_value"])


def downgrade() -> None:
    op.drop_index("ix_enrichment_diffs_entity_value", "enrichment_diffs")
    op.drop_index("ix_enrichment_diffs_provider", "enrichment_diffs")
    op.drop_table("enrichment_diffs")

    op.drop_column("ioc_sightings", "seeker_comment")
    op.drop_column("ioc_sightings", "sector_share")
    op.drop_column("ioc_sightings", "seeker_sector")

    op.drop_column("ioc_watches", "sector_context")
    op.drop_column("ioc_watches", "last_sighted_at")
    op.drop_column("ioc_watches", "sighting_count")

    op.drop_column("users", "business_sector")
