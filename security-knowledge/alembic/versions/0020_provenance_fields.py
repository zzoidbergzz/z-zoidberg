"""Add provenance fields to document_sections and evidence.

Adds page_number, byte_offset_start, byte_offset_end to document_sections
and page_number, byte_offset_start, byte_offset_end, artifact_id to evidence
to support precise source attribution and citation.

Revision ID: 0020
Revises: 0019
Create Date: 2026-05-08
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("document_sections", sa.Column("page_number", sa.Integer(), nullable=True))
    op.add_column("document_sections", sa.Column("byte_offset_start", sa.Integer(), nullable=True))
    op.add_column("document_sections", sa.Column("byte_offset_end", sa.Integer(), nullable=True))

    op.add_column("evidence", sa.Column("page_number", sa.Integer(), nullable=True))
    op.add_column("evidence", sa.Column("byte_offset_start", sa.Integer(), nullable=True))
    op.add_column("evidence", sa.Column("byte_offset_end", sa.Integer(), nullable=True))
    op.add_column("evidence", sa.Column("artifact_id", UUID(as_uuid=True), nullable=True))


def downgrade() -> None:
    op.drop_column("evidence", "artifact_id")
    op.drop_column("evidence", "byte_offset_end")
    op.drop_column("evidence", "byte_offset_start")
    op.drop_column("evidence", "page_number")
    op.drop_column("document_sections", "byte_offset_end")
    op.drop_column("document_sections", "byte_offset_start")
    op.drop_column("document_sections", "page_number")
