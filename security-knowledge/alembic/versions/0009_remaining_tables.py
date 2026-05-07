"""Remaining tables: change detection, detection rules, sync state, digests, LLM log

Revision ID: 0009
Revises: 0008
Create Date: 2026-05-07
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Change detection
    op.create_table(
        "claim_versions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("claim_id", UUID(as_uuid=True), sa.ForeignKey("claims.id", ondelete="CASCADE"), nullable=False),
        sa.Column("version_num", sa.Integer, nullable=False),
        sa.Column("value", JSONB, nullable=False),
        sa.Column("confidence", sa.Float, nullable=True),
        sa.Column("status", sa.String(20), nullable=True),
        sa.Column("changed_by", sa.String(255), nullable=True),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_claim_versions_claim_id", "claim_versions", ["claim_id"])

    op.create_table(
        "changes",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("entity_id", UUID(as_uuid=True), sa.ForeignKey("entities.id", ondelete="CASCADE"), nullable=True),
        sa.Column("claim_id", UUID(as_uuid=True), sa.ForeignKey("claims.id", ondelete="SET NULL"), nullable=True),
        sa.Column("change_type", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("details", JSONB, nullable=True),
        sa.Column("resolved", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_changes_tenant_id", "changes", ["tenant_id"])
    op.create_index("ix_changes_created_at", "changes", ["created_at"])

    # Detection rules
    op.create_table(
        "detection_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("entity_id", UUID(as_uuid=True), sa.ForeignKey("entities.id", ondelete="SET NULL"), nullable=True),
        sa.Column("claim_ids", JSONB, nullable=True),
        sa.Column("rule_type", sa.String(20), nullable=False),
        sa.Column("rule_content", sa.Text, nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_detection_rules_tenant_id", "detection_rules", ["tenant_id"])

    # Adapter sync state (NVD, GHSA, KEV, EUVD, TAXII, MISP, OpenCTI)
    op.create_table(
        "sync_state",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("adapter", sa.String(50), nullable=False),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cursor_value", sa.Text, nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="idle"),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "adapter", name="uq_sync_state_tenant_adapter"),
    )

    # TAXII collections (server mode)
    op.create_table(
        "taxii_collections",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("collection_id", sa.String(255), nullable=False),
        sa.Column("alias", sa.String(255), nullable=True),
        sa.Column("title", sa.String(512), nullable=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("can_read", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("can_write", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "collection_id", name="uq_taxii_collection"),
    )

    # Saved searches and digests
    op.create_table(
        "saved_searches",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("query_dsl", JSONB, nullable=False),
        sa.Column("schedule_cron", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "digest_subscriptions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("saved_search_id", UUID(as_uuid=True), sa.ForeignKey("saved_searches.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("channel", sa.String(20), nullable=False),
        sa.Column("config", JSONB, nullable=True),
        sa.Column("active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "digest_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("saved_search_id", UUID(as_uuid=True), sa.ForeignKey("saved_searches.id", ondelete="CASCADE"), nullable=False),
        sa.Column("run_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("result_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
    )

    # LLM safety: rejected extraction log
    op.create_table(
        "llm_rejection_log",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("prompt_hash", sa.String(64), nullable=False),
        sa.Column("response_text", sa.Text, nullable=True),
        sa.Column("rejection_reason", sa.String(255), nullable=False),
        sa.Column("model", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # Embedding cache (cross-tenant)
    op.execute("CREATE TABLE IF NOT EXISTS embedding_cache ("
               "id uuid PRIMARY KEY DEFAULT uuid_generate_v4(), "
               "text_hash varchar(64) NOT NULL UNIQUE, "
               "model varchar(100) NOT NULL, "
               "provider varchar(50) NOT NULL, "
               "created_at timestamptz NOT NULL DEFAULT now()"
               ")")
    op.execute("ALTER TABLE embedding_cache ADD COLUMN IF NOT EXISTS vector vector(1536)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS embedding_cache")
    op.drop_table("llm_rejection_log")
    op.drop_table("digest_runs")
    op.drop_table("digest_subscriptions")
    op.drop_table("saved_searches")
    op.drop_table("taxii_collections")
    op.drop_table("sync_state")
    op.drop_index("ix_detection_rules_tenant_id", "detection_rules")
    op.drop_table("detection_rules")
    op.drop_index("ix_changes_created_at", "changes")
    op.drop_index("ix_changes_tenant_id", "changes")
    op.drop_table("changes")
    op.drop_index("ix_claim_versions_claim_id", "claim_versions")
    op.drop_table("claim_versions")
