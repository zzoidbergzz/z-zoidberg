"""Sectors, sector_memberships, sector_invites tables + seed data

Revision ID: 0010
Revises: 0009
Create Date: 2026-05-07
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

SECTORS_SEED = [
    ("uk-general", "UK General", None),
    ("financial-banking", "Financial & Banking", "FS-ISAC"),
    ("retail", "Retail", None),
    ("infrastructure-energy", "Infrastructure & Energy", "E-ISAC"),
    ("healthcare", "Healthcare", "H-ISAC"),
    ("education", "Education", None),
    ("government-defence", "Government & Defence", None),
    ("technology", "Technology", None),
    ("transportation-logistics", "Transportation & Logistics", None),
    ("legal-professional", "Legal & Professional Services", None),
    ("manufacturing", "Manufacturing", None),
    ("media-entertainment", "Media & Entertainment", None),
    ("charity-ngo", "Charity & NGO", None),
]


def upgrade() -> None:
    op.create_table(
        "sectors",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("slug", sa.String(100), nullable=False, unique=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("isac_name", sa.String(100), nullable=True),
        sa.Column("info_sharing_enabled", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("member_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_sectors_slug", "sectors", ["slug"])

    op.create_table(
        "sector_memberships",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("sector_id", UUID(as_uuid=True), sa.ForeignKey("sectors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("org_name", sa.String(255), nullable=True),
        sa.Column("approved_by", UUID(as_uuid=True), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("invited_by", UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("sector_id", "user_id", name="uq_sector_membership"),
    )
    op.create_index("ix_sector_memberships_sector_id", "sector_memberships", ["sector_id"])
    op.create_index("ix_sector_memberships_user_id", "sector_memberships", ["user_id"])

    op.create_table(
        "sector_invites",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("sector_id", UUID(as_uuid=True), sa.ForeignKey("sectors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("invited_email", sa.String(255), nullable=False),
        sa.Column("invited_by", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token", sa.String(64), nullable=False, unique=True),
        sa.Column("used", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_sector_invites_token", "sector_invites", ["token"])

    # Seed sectors
    sectors_table = sa.table(
        "sectors",
        sa.column("slug", sa.String),
        sa.column("name", sa.String),
        sa.column("isac_name", sa.String),
    )
    op.bulk_insert(sectors_table, [
        {"slug": slug, "name": name, "isac_name": isac_name}
        for slug, name, isac_name in SECTORS_SEED
    ])


def downgrade() -> None:
    op.drop_index("ix_sector_invites_token", "sector_invites")
    op.drop_table("sector_invites")
    op.drop_index("ix_sector_memberships_user_id", "sector_memberships")
    op.drop_index("ix_sector_memberships_sector_id", "sector_memberships")
    op.drop_table("sector_memberships")
    op.drop_index("ix_sectors_slug", "sectors")
    op.drop_table("sectors")
