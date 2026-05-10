"""Add lifecycle_state to entities table.

Revision ID: 0033_entity_lifecycle_state
Revises: 0031_admin_invites
"""

from alembic import op
import sqlalchemy as sa

revision = "0033_entity_lifecycle_state"
down_revision = "0032_investigation_context_table"
branch_labels = None
depends_on = None

VALID_STATES = ("active", "expired", "retired", "false_positive", "benign")


def upgrade() -> None:
    op.execute("SET LOCAL app.bypass_rls = 'true'")

    op.add_column(
        "entities",
        sa.Column(
            "lifecycle_state",
            sa.String(20),
            nullable=False,
            server_default="active",
        ),
    )
    op.execute(
        "ALTER TABLE entities ADD CONSTRAINT chk_entity_lifecycle_state "
        "CHECK (lifecycle_state IN ('active','expired','retired','false_positive','benign'))"
    )
    op.create_index("ix_entities_lifecycle_state", "entities", ["lifecycle_state"])


def downgrade() -> None:
    op.execute("SET LOCAL app.bypass_rls = 'true'")
    op.drop_index("ix_entities_lifecycle_state", table_name="entities")
    op.execute("ALTER TABLE entities DROP CONSTRAINT IF EXISTS chk_entity_lifecycle_state")
    op.drop_column("entities", "lifecycle_state")
