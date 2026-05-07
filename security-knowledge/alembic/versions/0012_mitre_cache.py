"""MITRE ATT&CK cache table and mitre_attack_id on entities

Revision ID: 0012
Revises: 0011
Create Date: 2026-05-07
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMPTZ

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "mitre_stix_cache",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("domain", sa.String(50), nullable=False, unique=True),
        sa.Column("stix_version", sa.String(20), nullable=True),
        sa.Column("downloaded_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("file_path", sa.Text, nullable=True),
        sa.Column("object_count", sa.Integer, nullable=True),
    )

    op.add_column("entities", sa.Column("mitre_attack_id", sa.String(20), nullable=True))
    op.create_index("ix_entities_mitre_attack_id", "entities", ["mitre_attack_id"])


def downgrade() -> None:
    op.drop_index("ix_entities_mitre_attack_id", table_name="entities")
    op.drop_column("entities", "mitre_attack_id")
    op.drop_table("mitre_stix_cache")
