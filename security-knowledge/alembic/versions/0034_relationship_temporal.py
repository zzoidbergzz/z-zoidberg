"""Add temporal validity columns to relationships table.

Adds valid_from / valid_until so every edge has an observation window.
The graph and relationship endpoints accept ?at= to query a point-in-time
snapshot. The STIX builder maps these to start_time / stop_time on SROs.

Revision ID: 0034_relationship_temporal
Revises: 0033_entity_lifecycle_state
"""

from alembic import op
import sqlalchemy as sa

revision = "0034_relationship_temporal"
down_revision = "0033_entity_lifecycle_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("SET LOCAL app.bypass_rls = 'true'")

    op.add_column(
        "relationships",
        sa.Column(
            "valid_from",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
    )
    op.add_column(
        "relationships",
        sa.Column(
            "valid_until",
            sa.TIMESTAMP(timezone=True),
            nullable=True,
        ),
    )
    op.execute(
        """
        CREATE INDEX ix_relationships_temporal
          ON relationships (tenant_id, valid_from, valid_until)
        """
    )


def downgrade() -> None:
    op.execute("SET LOCAL app.bypass_rls = 'true'")
    op.execute("DROP INDEX IF EXISTS ix_relationships_temporal")
    op.drop_column("relationships", "valid_until")
    op.drop_column("relationships", "valid_from")
