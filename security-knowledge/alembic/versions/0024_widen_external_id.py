"""Widen corpus_documents.external_id from VARCHAR(128) to TEXT.

Some GCVE allocation IDs (e.g. GNA-1337 sequence) exceed 128 characters.

Revision ID: 0024
Revises: 0023
Create Date: 2025-07-12
"""

from alembic import op
import sqlalchemy as sa

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "corpus_documents",
        "external_id",
        type_=sa.Text(),
        existing_type=sa.String(128),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "corpus_documents",
        "external_id",
        type_=sa.String(128),
        existing_type=sa.Text(),
        existing_nullable=False,
    )
