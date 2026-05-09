"""Add watchlist collections and expiry settings.

Revision ID: 0028_watchlists
Revises: 0027
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column("watchlist_settings", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )

    op.create_table(
        "watchlists",
        sa.Column("id", sa.UUID(), nullable=False, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("owner_user_id", sa.UUID(), nullable=True),
        sa.Column("created_by_user_id", sa.UUID(), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("scope", sa.String(length=20), nullable=False, server_default="personal"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("expiry_hours", sa.Integer(), nullable=False, server_default="12960"),
        sa.Column("export_formats", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "scope", "owner_user_id", "name", name="uq_watchlists_tenant_scope_owner_name"),
    )
    op.create_index("ix_watchlists_tenant_id", "watchlists", ["tenant_id"])
    op.create_index("ix_watchlists_owner_user_id", "watchlists", ["owner_user_id"])

    op.create_table(
        "watchlist_export_tokens",
        sa.Column("id", sa.UUID(), nullable=False, server_default=sa.text("gen_random_uuid()")),
        sa.Column("watchlist_id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("created_by_user_id", sa.UUID(), nullable=True),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("formats", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["watchlist_id"], ["watchlists.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("token_hash", name="uq_watchlist_export_tokens_token_hash"),
    )
    op.create_index("ix_watchlist_export_tokens_watchlist_id", "watchlist_export_tokens", ["watchlist_id"])
    op.create_index("ix_watchlist_export_tokens_tenant_id", "watchlist_export_tokens", ["tenant_id"])

    op.add_column("ioc_watches", sa.Column("watchlist_id", sa.UUID(), nullable=True))
    op.create_index("ix_ioc_watches_watchlist_id", "ioc_watches", ["watchlist_id"])
    op.drop_constraint("uq_ioc_watch_user_ioc_mode", "ioc_watches", type_="unique")
    op.create_unique_constraint("uq_ioc_watch_list_ioc_mode", "ioc_watches", ["watchlist_id", "ioc_value_hash", "mode"])
    op.create_foreign_key("fk_ioc_watches_watchlist_id", "ioc_watches", "watchlists", ["watchlist_id"], ["id"], ondelete="CASCADE")


def downgrade() -> None:
    op.drop_constraint("uq_ioc_watch_list_ioc_mode", "ioc_watches", type_="unique")
    op.drop_constraint("fk_ioc_watches_watchlist_id", "ioc_watches", type_="foreignkey")
    op.drop_index("ix_ioc_watches_watchlist_id", table_name="ioc_watches")
    op.drop_column("ioc_watches", "watchlist_id")
    op.drop_index("ix_watchlist_export_tokens_tenant_id", table_name="watchlist_export_tokens")
    op.drop_index("ix_watchlist_export_tokens_watchlist_id", table_name="watchlist_export_tokens")
    op.drop_table("watchlist_export_tokens")
    op.drop_index("ix_watchlists_owner_user_id", table_name="watchlists")
    op.drop_index("ix_watchlists_tenant_id", table_name="watchlists")
    op.drop_table("watchlists")
    op.drop_column("tenants", "watchlist_settings")
