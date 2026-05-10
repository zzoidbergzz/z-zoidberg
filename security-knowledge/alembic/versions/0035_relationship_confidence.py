"""Add confidence_level enum and source_type to relationships.

Replaces the raw float confidence with a categorical level for display,
keeping the original float for backward compat during the deprecation window.
Backfills existing rows from the float value.

Revision ID: 0035_relationship_confidence
Revises: 0034_relationship_temporal
"""

from alembic import op
import sqlalchemy as sa

revision = "0035_relationship_confidence"
down_revision = "0034_relationship_temporal"
branch_labels = None
depends_on = None

VALID_LEVELS = ("low", "medium", "high", "unknown")


def upgrade() -> None:
    op.execute("SET LOCAL app.bypass_rls = 'true'")

    op.add_column(
        "relationships",
        sa.Column(
            "confidence_level",
            sa.String(10),
            nullable=False,
            server_default="medium",
        ),
    )
    op.execute(
        "ALTER TABLE relationships ADD CONSTRAINT chk_rel_confidence_level "
        "CHECK (confidence_level IN ('low','medium','high','unknown'))"
    )

    op.add_column(
        "relationships",
        sa.Column("source_type", sa.String(50), nullable=True),
    )

    # Backfill confidence_level from existing float confidence column
    op.execute(
        """
        UPDATE relationships
           SET confidence_level = CASE
                 WHEN confidence >= 0.8 THEN 'high'
                 WHEN confidence >= 0.4 THEN 'medium'
                 ELSE 'low'
               END
        """
    )

    op.create_index("ix_relationships_confidence_level", "relationships", ["confidence_level"])


def downgrade() -> None:
    op.execute("SET LOCAL app.bypass_rls = 'true'")
    op.drop_index("ix_relationships_confidence_level", table_name="relationships")
    op.execute("ALTER TABLE relationships DROP CONSTRAINT IF EXISTS chk_rel_confidence_level")
    op.drop_column("relationships", "source_type")
    op.drop_column("relationships", "confidence_level")
