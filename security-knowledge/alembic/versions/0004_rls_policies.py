"""Row Level Security policies for tenant isolation

Revision ID: 0004
Revises: 0003
Create Date: 2026-05-07
"""
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

TENANT_TABLES = [
    "source_records",
    "entities",
    "claims",
    "relationships",
    "ingestion_jobs",
    "audit_events",
]


def upgrade() -> None:
    # Create the setter function used by the session middleware
    op.execute("""
        CREATE OR REPLACE FUNCTION app_set_tenant_id(p_tenant_id text) RETURNS void AS $$
        BEGIN
            PERFORM set_config('app.tenant_id', p_tenant_id, true);
        END;
        $$ LANGUAGE plpgsql;
    """)

    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""
            CREATE POLICY tenant_isolation ON {table}
                USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
                WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid)
        """)
        # Allow superuser / migration user to bypass RLS
        op.execute(f"""
            CREATE POLICY superuser_bypass ON {table}
                TO current_user
                USING (current_setting('app.bypass_rls', true) = 'true')
        """)


def downgrade() -> None:
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS superuser_bypass ON {table}")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    op.execute("DROP FUNCTION IF EXISTS app_set_tenant_id(text)")
