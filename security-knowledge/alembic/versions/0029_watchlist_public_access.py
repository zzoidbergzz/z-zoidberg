"""Add public short-name access to watchlists.

Revision ID: 0029_watchlist_public_access
Revises: 0028
"""

from alembic import op
import sqlalchemy as sa

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("watchlists", sa.Column("public_slug", sa.String(length=255), nullable=True))
    op.add_column(
        "watchlists",
        sa.Column("allow_unauthenticated", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.create_unique_constraint("uq_watchlists_public_slug", "watchlists", ["public_slug"])
    op.create_index("ix_watchlists_public_slug", "watchlists", ["public_slug"])


def downgrade() -> None:
    op.drop_index("ix_watchlists_public_slug", table_name="watchlists")
    op.drop_constraint("uq_watchlists_public_slug", "watchlists", type_="unique")
    op.drop_column("watchlists", "allow_unauthenticated")
    op.drop_column("watchlists", "public_slug")
