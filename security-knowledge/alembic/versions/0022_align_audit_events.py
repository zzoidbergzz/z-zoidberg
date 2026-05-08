"""Align audit_events to the AuditEvent model (ADD-only).

The live DB has actor_id/actor_kind/resource_kind columns from an old
schema, but the worker code (and AuditEvent model) writes
actor/resource_type/ip_address/user_agent. Add the missing columns as
nullable so both shapes coexist; preserve all legacy columns.

Revision ID: 0022
Revises: 0021
"""
import sqlalchemy as sa

from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_events", sa.Column("actor", sa.String(255), nullable=True))
    op.add_column("audit_events", sa.Column("resource_type", sa.String(100), nullable=True))
    op.add_column("audit_events", sa.Column("ip_address", sa.String(50), nullable=True))
    op.add_column("audit_events", sa.Column("user_agent", sa.Text(), nullable=True))
    op.add_column(
        "audit_events",
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_audit_events_action", "audit_events", ["action"])


def downgrade() -> None:
    op.drop_index("ix_audit_events_action", table_name="audit_events")
    for col in ("actor", "resource_type", "ip_address", "user_agent", "updated_at"):
        op.drop_column("audit_events", col)
