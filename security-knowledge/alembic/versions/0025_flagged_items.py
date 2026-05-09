"""Add flagged_items table for feed ticker flag system.

Revision ID: 0025_flagged_items
Revises: 0024_widen_external_id
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "flagged_items",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True, index=True),
        sa.Column("source_type", sa.String(50), nullable=False, index=True),
        sa.Column("title", sa.String(1024), nullable=False),
        sa.Column("body", sa.Text, nullable=True),
        sa.Column("url", sa.Text, nullable=True),
        sa.Column("external_id", sa.String(512), nullable=True, index=True),
        sa.Column("flagged_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acked_by", sa.String(256), nullable=True),
        sa.Column("acked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("flagged_items")
