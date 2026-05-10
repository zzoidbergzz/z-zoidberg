"""Add tenant invite rules for auto-approval.

Revision ID: 0031_admin_invites
Revises: 0030_watchlist_item_comment
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0031_admin_invites"
down_revision = "0030_watchlist_item_comment"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenant_invite_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("rule_type", sa.String(length=20), nullable=False),
        sa.Column("rule_value", sa.String(length=255), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "rule_type", "rule_value", name="uq_tenant_invite_rule"),
    )
    op.create_index("ix_tenant_invite_rules_tenant_id", "tenant_invite_rules", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_tenant_invite_rules_tenant_id", table_name="tenant_invite_rules")
    op.drop_table("tenant_invite_rules")
