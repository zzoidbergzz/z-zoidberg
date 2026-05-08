"""Add corpus_documents table for historical security corpora.

Creates:
- corpus_documents: CVE list V5, GCVE allocations, Exploit-DB records
- GIN index on search_vector tsvector column
- trigger to keep search_vector up-to-date from title/external_id/summary/body_text

Revision ID: 0023
Revises: 0022
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "corpus_documents",
        sa.Column("id", sa.UUID(), nullable=False, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("corpus", sa.String(32), nullable=False),
        sa.Column("external_id", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("body_text", sa.Text(), nullable=True),
        sa.Column("raw_json", JSONB(), nullable=True),
        sa.Column("source_path", sa.Text(), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("search_vector", TSVECTOR(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # Indexes
    op.create_index("ix_corpus_documents_tenant_id", "corpus_documents", ["tenant_id"])
    op.create_index("ix_corpus_documents_corpus", "corpus_documents", ["corpus"])
    op.create_index("ix_corpus_documents_external_id", "corpus_documents", ["external_id"])
    op.create_index("ix_corpus_documents_published_at", "corpus_documents", ["published_at"])
    op.create_index(
        "ix_corpus_documents_search_vector",
        "corpus_documents",
        ["search_vector"],
        postgresql_using="gin",
    )
    op.create_unique_constraint(
        "uq_corpus_external_id", "corpus_documents", ["corpus", "external_id"]
    )

    # Trigger function to maintain search_vector
    op.execute(
        """
        CREATE OR REPLACE FUNCTION corpus_documents_search_vector_update()
        RETURNS trigger AS $$
        BEGIN
            NEW.search_vector :=
                setweight(to_tsvector('english', coalesce(NEW.external_id, '')), 'A') ||
                setweight(to_tsvector('english', coalesce(NEW.title, '')), 'A') ||
                setweight(to_tsvector('english', coalesce(NEW.summary, '')), 'B') ||
                setweight(to_tsvector('english', coalesce(left(NEW.body_text, 100000), '')), 'C');
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER corpus_documents_search_vector_trigger
        BEFORE INSERT OR UPDATE ON corpus_documents
        FOR EACH ROW EXECUTE FUNCTION corpus_documents_search_vector_update();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS corpus_documents_search_vector_trigger ON corpus_documents")
    op.execute("DROP FUNCTION IF EXISTS corpus_documents_search_vector_update()")
    op.drop_table("corpus_documents")
