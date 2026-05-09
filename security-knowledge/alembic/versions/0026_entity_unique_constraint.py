"""Deduplicate entities and add UNIQUE(tenant_id, kind, canonical_name).

Without this constraint, two ingestion workers can race on the read-then-insert
upsert in worker.py, producing duplicate entities. Subsequent ingests then crash
with `MultipleResultsFound` from `scalar_one_or_none()` (24k+ failed jobs as of
2026-05-09).

This migration:
  1. Builds a mapping (duplicate_id -> canonical_id = MIN(id) per group).
  2. Repoints all FK references onto the canonical id, handling composite-PK
     tables via INSERT … ON CONFLICT DO NOTHING + DELETE.
  3. Deletes the now-orphaned duplicate entity rows.
  4. Adds the unique index that prevents the race going forward.

Revision ID: 0026_entity_unique
Revises: 0025
"""
from alembic import op


revision = "0026_entity_unique"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("SET LOCAL app.bypass_rls = 'true'")

    # 1. Build dup -> canonical map in a temp table.
    op.execute(
        """
        CREATE TEMP TABLE _entity_dedup_map ON COMMIT DROP AS
        WITH ranked AS (
            SELECT
                id,
                tenant_id,
                kind,
                canonical_name,
                FIRST_VALUE(id) OVER (
                    PARTITION BY tenant_id, kind, canonical_name
                    ORDER BY created_at, id::text
                ) AS canon_id
            FROM entities
        )
        SELECT id AS dup_id, canon_id
          FROM ranked
         WHERE id <> canon_id;
        """
    )

    # 2a. Simple FKs — UPDATE in place.
    for table, col in (
        ("claims", "entity_id"),
        ("relationships", "from_entity_id"),
        ("relationships", "to_entity_id"),
        ("changes", "entity_id"),
        ("detection_rules", "entity_id"),
    ):
        op.execute(
            f"""
            UPDATE {table} t
               SET {col} = m.canon_id
              FROM _entity_dedup_map m
             WHERE t.{col} = m.dup_id;
            """
        )

    # 2b. Composite-PK FKs — INSERT canonical rewrite then DELETE duplicates,
    #     so unique-PK collisions don't blow up.
    op.execute(
        """
        INSERT INTO investigation_entities (investigation_id, entity_id, added_at, added_by)
        SELECT ie.investigation_id, m.canon_id, ie.added_at, ie.added_by
          FROM investigation_entities ie
          JOIN _entity_dedup_map m ON m.dup_id = ie.entity_id
        ON CONFLICT (investigation_id, entity_id) DO NOTHING;
        """
    )
    op.execute(
        """
        DELETE FROM investigation_entities ie
         USING _entity_dedup_map m
         WHERE ie.entity_id = m.dup_id;
        """
    )

    op.execute(
        """
        INSERT INTO entity_lookup_state (entity_id, tenant_id, last_dispatch_at, last_force_repoll_at)
        SELECT m.canon_id, els.tenant_id, els.last_dispatch_at, els.last_force_repoll_at
          FROM entity_lookup_state els
          JOIN _entity_dedup_map m ON m.dup_id = els.entity_id
        ON CONFLICT (entity_id, tenant_id) DO NOTHING;
        """
    )
    op.execute(
        """
        DELETE FROM entity_lookup_state els
         USING _entity_dedup_map m
         WHERE els.entity_id = m.dup_id;
        """
    )

    # 3. Drop the now-orphaned duplicate entity rows.
    op.execute(
        """
        DELETE FROM entities e
         USING _entity_dedup_map m
         WHERE e.id = m.dup_id;
        """
    )

    # 4. Add the unique constraint that prevents the race.
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_entities_tenant_kind_canonical
        ON entities (tenant_id, kind, canonical_name);
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_entities_tenant_kind_canonical;")
