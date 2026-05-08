"""Add missing columns to ingestion_jobs

Revision ID: 0013
Revises: 0012
Create Date: 2026-05-07
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # source_id: add without FK since the table is source_records, not sources
    op.add_column("ingestion_jobs", sa.Column("source_id", UUID(as_uuid=True), nullable=True))
    op.add_column("ingestion_jobs", sa.Column("job_type", sa.String(100), nullable=False, server_default="ingest_url"))
    op.add_column("ingestion_jobs", sa.Column("payload", JSONB, nullable=False, server_default="{}"))
    op.add_column("ingestion_jobs", sa.Column("result", JSONB, nullable=False, server_default="{}"))
    op.add_column("ingestion_jobs", sa.Column("retry_count", sa.Integer, nullable=False, server_default="0"))
    op.add_column("ingestion_jobs", sa.Column("arq_job_id", sa.String(255), nullable=True))


def downgrade() -> None:
    op.drop_column("ingestion_jobs", "arq_job_id")
    op.drop_column("ingestion_jobs", "retry_count")
    op.drop_column("ingestion_jobs", "result")
    op.drop_column("ingestion_jobs", "payload")
    op.drop_column("ingestion_jobs", "job_type")
    op.drop_column("ingestion_jobs", "source_id")
