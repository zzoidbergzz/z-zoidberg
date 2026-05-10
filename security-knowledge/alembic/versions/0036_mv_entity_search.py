"""Create mv_entity_search materialized view for fast entity search.

Collapses the three correlated subqueries in _ENTITY_SQL into a single
pre-joined MV that can be refreshed concurrently every few minutes.

Requires: pg_trgm extension (added in migration 0005 or earlier).

Revision ID: 0036_mv_entity_search
Revises: 0035_relationship_confidence
"""

from alembic import op

revision = "0036_mv_entity_search"
down_revision = "0035_relationship_confidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("SET LOCAL app.bypass_rls = 'true'")

    op.execute(
        """
        CREATE MATERIALIZED VIEW IF NOT EXISTS mv_entity_search AS
        SELECT
            e.id,
            e.tenant_id,
            e.kind,
            e.canonical_name,
            e.mitre_attack_id,
            e.external_refs,
            e.lifecycle_state,
            e.updated_at,
            e.search_vector,
            c.description     AS latest_claim_desc,
            c.tags            AS latest_tags,
            c.confidence      AS latest_confidence
        FROM entities e
        LEFT JOIN LATERAL (
            SELECT
                value->>'assertion'  AS description,
                value->'tags'        AS tags,
                value->>'confidence' AS confidence
            FROM claims
            WHERE entity_id = e.id
              AND claim_type IN (
                  'vulnerability_detail','technique_detail','actor_profile',
                  'report_detail','organization_profile','product_detail',
                  'framework_detail','tool_capability','detection_detail'
              )
            ORDER BY created_at DESC
            LIMIT 1
        ) c ON true
        """
    )

    # Unique index required for CONCURRENT refresh
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS uix_mv_entity_search_id ON mv_entity_search (id)")
    # FTS index on the pre-built tsvector
    op.execute("CREATE INDEX IF NOT EXISTS ix_mv_entity_search_fts ON mv_entity_search USING GIN (search_vector)")
    # Trigram index for similarity()
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_mv_entity_search_trgm "
        "ON mv_entity_search USING GIN (canonical_name gin_trgm_ops)"
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_mv_entity_search_tenant ON mv_entity_search (tenant_id)")


def downgrade() -> None:
    op.execute("DROP MATERIALIZED VIEW IF EXISTS mv_entity_search CASCADE")
