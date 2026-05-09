"""Add per-item comments to IOC watch entries.

Revision ID: 0030_watchlist_item_comment
Revises: 0029
"""

from alembic import op
import sqlalchemy as sa

revision = "0030_watchlist_item_comment"
down_revision = "0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ioc_watches", sa.Column("comment", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("ioc_watches", "comment")
