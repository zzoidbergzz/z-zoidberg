"""Fix enrichment_usage.date column type: cast from DATE to VARCHAR(10).

The SQLAlchemy model maps date as String(10) (ISO-8601 date string) but
the original migration created it as a SQL DATE type.  Cast in-place.

Revision ID: 0018
Revises: 0017
Create Date: 2026-05-08
"""
from alembic import op
import sqlalchemy as sa

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "enrichment_usage",
        "date",
        type_=sa.String(10),
        postgresql_using="date::text",
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "enrichment_usage",
        "date",
        type_=sa.Date(),
        postgresql_using="date::date",
        existing_nullable=False,
    )
