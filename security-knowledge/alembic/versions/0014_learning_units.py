"""Add learning_units table for structured knowledge packs.

Revision ID: 0014
Revises: 0013
Create Date: 2026-05-24
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "learning_units",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("learning_unit_id", sa.String(256), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("level", sa.String(64), nullable=False, server_default="foundation"),
        sa.Column("roles", JSONB, nullable=False, server_default="[]"),
        sa.Column("domains", JSONB, nullable=False, server_default="[]"),
        sa.Column("objectives", JSONB, nullable=False, server_default="[]"),
        sa.Column("prerequisites", JSONB, nullable=False, server_default="[]"),
        sa.Column("source_refs", JSONB, nullable=False, server_default="[]"),
        sa.Column("entity_refs", JSONB, nullable=False, server_default="[]"),
        sa.Column("fact_refs", JSONB, nullable=False, server_default="[]"),
        sa.Column("lab", JSONB, nullable=False, server_default="{}"),
        sa.Column("assessment", JSONB, nullable=False, server_default="[]"),
        sa.Column("retrieval_tags", JSONB, nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "learning_unit_id", name="uq_learning_units_tenant_lu_id"),
    )
    op.create_index("ix_learning_units_tenant_id", "learning_units", ["tenant_id"])
    op.create_index("ix_learning_units_learning_unit_id", "learning_units", ["learning_unit_id"])


def downgrade() -> None:
    op.drop_index("ix_learning_units_learning_unit_id", table_name="learning_units")
    op.drop_index("ix_learning_units_tenant_id", table_name="learning_units")
    op.drop_table("learning_units")
