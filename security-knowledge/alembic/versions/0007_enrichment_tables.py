"""Enrichment tables: cache, usage tracking, and BYOK-aware credit routing

Revision ID: 0007
Revises: 0006
Create Date: 2026-05-07
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Shared enrichment cache — cross-tenant, keyed by provider + ioc value hash
    # All tenants benefit from any user's enrichment hit
    op.create_table(
        "enrichment_cache",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("entity_kind", sa.String(50), nullable=False),
        sa.Column("entity_value_hash", sa.String(64), nullable=False),  # sha256 of normalised value
        sa.Column("entity_value", sa.Text, nullable=False),
        sa.Column("raw_response", JSONB, nullable=True),
        sa.Column("normalized", JSONB, nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        # Which tenant/user's credits were consumed to populate this entry
        sa.Column("populated_by_tenant_id", UUID(as_uuid=True), nullable=True),
        sa.Column("populated_by_user_id", UUID(as_uuid=True), nullable=True),
        sa.Column("used_byok", sa.Boolean, nullable=False, server_default="false"),
        sa.UniqueConstraint("provider", "entity_value_hash", name="uq_enrichment_cache_provider_value"),
    )
    op.create_index("ix_enrichment_cache_lookup", "enrichment_cache", ["provider", "entity_value_hash"])
    op.create_index("ix_enrichment_cache_expires_at", "enrichment_cache", ["expires_at"])

    # Per-user, per-provider usage tracking (for BYOK credit accounting)
    op.create_table(
        "enrichment_usage",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("used_byok", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("date", sa.Date, nullable=False),
        sa.Column("requests_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("cache_hits", sa.Integer, nullable=False, server_default="0"),
        sa.UniqueConstraint("provider", "tenant_id", "user_id", "date", name="uq_enrichment_usage_day"),
    )
    op.create_index("ix_enrichment_usage_tenant_date", "enrichment_usage", ["tenant_id", "date"])


def downgrade() -> None:
    op.drop_index("ix_enrichment_usage_tenant_date", "enrichment_usage")
    op.drop_table("enrichment_usage")
    op.drop_index("ix_enrichment_cache_expires_at", "enrichment_cache")
    op.drop_index("ix_enrichment_cache_lookup", "enrichment_cache")
    op.drop_table("enrichment_cache")
