"""Add investigations, investigation_entities, entity_lookup_state, fingerprint_events.

Revision ID: 0015
Revises: 0014
Create Date: 2026-05-24
"""
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE investigations (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            created_by UUID REFERENCES users(id),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    op.execute("CREATE INDEX ix_investigations_tenant ON investigations(tenant_id)")

    op.execute("""
        CREATE TABLE investigation_entities (
            investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
            entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
            added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            added_by UUID REFERENCES users(id),
            PRIMARY KEY (investigation_id, entity_id)
        )
    """)

    op.execute("""
        CREATE TABLE entity_lookup_state (
            entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
            tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            last_dispatch_at TIMESTAMPTZ,
            last_force_repoll_at TIMESTAMPTZ,
            PRIMARY KEY (entity_id, tenant_id)
        )
    """)

    op.execute("""
        CREATE TABLE fingerprint_events (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID REFERENCES users(id),
            tenant_id UUID REFERENCES tenants(id),
            ip_address VARCHAR(45),
            user_agent TEXT,
            fingerprint_hash VARCHAR(128),
            path TEXT,
            server_data JSONB,
            client_data JSONB,
            combined_data JSONB,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    op.execute("CREATE INDEX ix_fingerprint_events_tenant ON fingerprint_events(tenant_id)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_fingerprint_events_tenant")
    op.execute("DROP TABLE IF EXISTS fingerprint_events")
    op.execute("DROP TABLE IF EXISTS entity_lookup_state")
    op.execute("DROP TABLE IF EXISTS investigation_entities")
    op.execute("DROP INDEX IF EXISTS ix_investigations_tenant")
    op.execute("DROP TABLE IF EXISTS investigations")
