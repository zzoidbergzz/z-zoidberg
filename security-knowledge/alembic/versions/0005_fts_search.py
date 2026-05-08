"""FTS search vectors: tsvector columns, GIN indexes, update triggers

Revision ID: 0005
Revises: 0004
Create Date: 2026-05-07
"""
from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # search_vector columns
    op.execute("ALTER TABLE entities ADD COLUMN IF NOT EXISTS search_vector tsvector")
    op.execute("ALTER TABLE claims ADD COLUMN IF NOT EXISTS search_vector tsvector")
    op.execute("ALTER TABLE source_records ADD COLUMN IF NOT EXISTS search_vector tsvector")

    # GIN indexes for FTS
    op.execute("CREATE INDEX IF NOT EXISTS ix_entities_search_vector ON entities USING GIN(search_vector)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_claims_search_vector ON claims USING GIN(search_vector)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_source_records_search_vector ON source_records USING GIN(search_vector)")

    # GIN trigram indexes for fuzzy matching
    op.execute("CREATE INDEX IF NOT EXISTS ix_entities_canonical_trgm ON entities USING GIN(canonical_name gin_trgm_ops)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_source_records_title_trgm ON source_records USING GIN(title gin_trgm_ops)")

    # Trigger function: entities
    op.execute("""
        CREATE OR REPLACE FUNCTION entities_search_vector_update() RETURNS trigger AS $$
        BEGIN
            NEW.search_vector :=
                setweight(to_tsvector('english', coalesce(NEW.canonical_name, '')), 'A') ||
                setweight(to_tsvector('english', coalesce(NEW.kind, '')), 'B');
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER entities_search_vector_trigger
        BEFORE INSERT OR UPDATE ON entities
        FOR EACH ROW EXECUTE FUNCTION entities_search_vector_update();
    """)

    # Trigger function: claims (value is jsonb, coerce to text)
    op.execute("""
        CREATE OR REPLACE FUNCTION claims_search_vector_update() RETURNS trigger AS $$
        BEGIN
            NEW.search_vector :=
                setweight(to_tsvector('english', coalesce(NEW.claim_type, '')), 'A') ||
                setweight(to_tsvector('english', coalesce(NEW.value::text, '')), 'B');
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER claims_search_vector_trigger
        BEFORE INSERT OR UPDATE ON claims
        FOR EACH ROW EXECUTE FUNCTION claims_search_vector_update();
    """)

    # Trigger function: source_records
    op.execute("""
        CREATE OR REPLACE FUNCTION source_records_search_vector_update() RETURNS trigger AS $$
        BEGIN
            NEW.search_vector :=
                setweight(to_tsvector('english', coalesce(NEW.title, '')), 'A') ||
                setweight(to_tsvector('english', coalesce(NEW.url, '')), 'B');
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER source_records_search_vector_trigger
        BEFORE INSERT OR UPDATE ON source_records
        FOR EACH ROW EXECUTE FUNCTION source_records_search_vector_update();
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS source_records_search_vector_trigger ON source_records")
    op.execute("DROP TRIGGER IF EXISTS claims_search_vector_trigger ON claims")
    op.execute("DROP TRIGGER IF EXISTS entities_search_vector_trigger ON entities")
    op.execute("DROP FUNCTION IF EXISTS source_records_search_vector_update()")
    op.execute("DROP FUNCTION IF EXISTS claims_search_vector_update()")
    op.execute("DROP FUNCTION IF EXISTS entities_search_vector_update()")
    op.execute("DROP INDEX IF EXISTS ix_source_records_title_trgm")
    op.execute("DROP INDEX IF EXISTS ix_entities_canonical_trgm")
    op.execute("DROP INDEX IF EXISTS ix_source_records_search_vector")
    op.execute("DROP INDEX IF EXISTS ix_claims_search_vector")
    op.execute("DROP INDEX IF EXISTS ix_entities_search_vector")
    op.execute("ALTER TABLE source_records DROP COLUMN IF EXISTS search_vector")
    op.execute("ALTER TABLE claims DROP COLUMN IF EXISTS search_vector")
    op.execute("ALTER TABLE entities DROP COLUMN IF EXISTS search_vector")
