"""Move investigation_context_for relationships to a dedicated lightweight table.

The `relationships` table had 99,433 `investigation_context_for` edges (80% of
all edges). These are weak entity-to-technique context links created by
inter_knowledge_enrichment.py — not semantic threat-intel edges. Keeping them
in `relationships` makes BFS expensive and the graph a hairball.

This migration:
1. Creates `entity_context_links` to store these weak context edges.
2. Copies existing `investigation_context_for` rows there.
3. Deletes them from `relationships`.

The scripts/inter_knowledge_enrichment.py writer is updated separately to
insert into `entity_context_links` directly.

Revision ID: 0032_investigation_context_table
Revises: 0031_admin_invites
"""
from alembic import op
import sqlalchemy as sa

revision = "0032_investigation_context_table"
down_revision = "0031_admin_invites"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Create the lightweight context table.
    op.create_table(
        "entity_context_links",
        sa.Column("id", sa.UUID(), nullable=False, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("from_entity_id", sa.UUID(), nullable=False),
        sa.Column("to_entity_id", sa.UUID(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.8"),
        sa.Column("added_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["from_entity_id"], ["entities.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["to_entity_id"], ["entities.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_ecl_tenant_from", "entity_context_links", ["tenant_id", "from_entity_id"])
    op.create_index("ix_ecl_tenant_to", "entity_context_links", ["tenant_id", "to_entity_id"])
    op.create_unique_constraint(
        "uq_ecl_tenant_from_to",
        "entity_context_links",
        ["tenant_id", "from_entity_id", "to_entity_id"],
    )

    # 2. Enable RLS bypass so we can move all tenant rows.
    op.execute("SET LOCAL app.bypass_rls = 'true'")

    # 3. Copy existing investigation_context_for rows.
    op.execute(
        """
        INSERT INTO entity_context_links (tenant_id, from_entity_id, to_entity_id, confidence, added_at)
        SELECT tenant_id, from_entity_id, to_entity_id, COALESCE(confidence, 0.8), COALESCE(created_at, now())
          FROM relationships
         WHERE kind = 'investigation_context_for'
        ON CONFLICT (tenant_id, from_entity_id, to_entity_id) DO NOTHING
        """
    )

    # 4. Delete from relationships — drops 99K rows, reduces table by 80%.
    op.execute("DELETE FROM relationships WHERE kind = 'investigation_context_for'")


def downgrade() -> None:
    # Restore investigation_context_for rows from entity_context_links.
    op.execute("SET LOCAL app.bypass_rls = 'true'")
    op.execute(
        """
        INSERT INTO relationships (tenant_id, from_entity_id, to_entity_id, kind, confidence, created_at)
        SELECT tenant_id, from_entity_id, to_entity_id, 'investigation_context_for', confidence, added_at
          FROM entity_context_links
        ON CONFLICT DO NOTHING
        """
    )
    op.drop_table("entity_context_links")
