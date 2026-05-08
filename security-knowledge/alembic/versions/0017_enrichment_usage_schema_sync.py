"""Sync enrichment_usage schema with current SQLAlchemy model.

The original 0007 migration used different column names (requests_count
instead of count, no budget, no created_at/updated_at).

Revision ID: 0017
Revises: 0016
Create Date: 2026-05-08
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add count (the model uses this; requests_count is the old name)
    op.add_column(
        "enrichment_usage",
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
    )
    # Back-fill from old column
    op.execute("UPDATE enrichment_usage SET count = requests_count WHERE requests_count IS NOT NULL")

    # Add budget with generous default
    op.add_column(
        "enrichment_usage",
        sa.Column("budget", sa.Integer(), nullable=False, server_default="1000"),
    )

    # Add TimestampMixin columns
    op.add_column(
        "enrichment_usage",
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.add_column(
        "enrichment_usage",
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )


def downgrade() -> None:
    op.drop_column("enrichment_usage", "count")
    op.drop_column("enrichment_usage", "budget")
    op.drop_column("enrichment_usage", "created_at")
    op.drop_column("enrichment_usage", "updated_at")
