"""Align ingestion subsystem schema to current models + add FTS.

Brings the ``source_records``, ``fetch_outcomes``, ``parsed_documents``,
``document_sections`` and ``evidence`` tables in line with the SQLAlchemy
models that the worker, routers and CLI already write to.

Strategy:
* **ADD-only**: every legacy column is preserved (data retention principle).
  Legacy NOT-NULL constraints are relaxed so the new code path can insert
  without populating deprecated columns.
* **Rename only** ``fetch_outcomes.source_record_id`` → ``source_id`` so the
  model attribute name matches the DB column name. Empty table → safe.
* **Auto-fill ``source_records.url_hash``** via trigger so the application
  doesn't need to know about it (legacy NOT NULL preserved).
* **Add tsvector FTS** to ``parsed_documents`` and ``document_sections`` so
  every ingested article + section is freely full-text searchable.

All affected tables verified empty (0 rows) at migration write time, so the
forward-only column relaxations are not destructive.

Revision ID: 0021
Revises: 0020
Create Date: 2026-05-08
"""
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # source_records — feed/source registry
    # ------------------------------------------------------------------
    op.add_column(
        "source_records",
        sa.Column("source_type", sa.String(50), nullable=False, server_default="generic"),
    )
    op.add_column(
        "source_records",
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.add_column(
        "source_records",
        sa.Column("last_fetched_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "source_records",
        sa.Column("fetch_interval_seconds", sa.Integer(), nullable=False, server_default="3600"),
    )
    # Auto-populate legacy url_hash so the model doesn't have to.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION source_records_url_hash_trigger() RETURNS trigger AS $$
        BEGIN
            IF NEW.url_hash IS NULL OR NEW.url_hash = '' THEN
                NEW.url_hash := encode(digest(NEW.url, 'sha256'), 'hex');
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    # pgcrypto provides digest()
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    op.execute(
        """
        CREATE TRIGGER source_records_url_hash_autofill
        BEFORE INSERT OR UPDATE ON source_records
        FOR EACH ROW EXECUTE FUNCTION source_records_url_hash_trigger();
        """
    )
    op.create_index(
        "ix_source_records_active_due",
        "source_records",
        ["active", "last_fetched_at"],
    )

    # ------------------------------------------------------------------
    # fetch_outcomes — per-fetch telemetry
    # ------------------------------------------------------------------
    op.alter_column("fetch_outcomes", "source_record_id", new_column_name="source_id")
    op.add_column(
        "fetch_outcomes",
        sa.Column("status", sa.String(50), nullable=False, server_default="ok"),
    )
    op.add_column("fetch_outcomes", sa.Column("error_message", sa.Text(), nullable=True))
    op.add_column(
        "fetch_outcomes",
        sa.Column("items_fetched", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "fetch_outcomes",
        sa.Column("duration_ms", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "fetch_outcomes",
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.add_column(
        "fetch_outcomes",
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_fetch_outcomes_source_created", "fetch_outcomes", ["source_id", "created_at"])

    # ------------------------------------------------------------------
    # parsed_documents — top-level ingested article
    # ------------------------------------------------------------------
    op.alter_column("parsed_documents", "raw_object_id", nullable=True)
    op.add_column("parsed_documents", sa.Column("tenant_id", UUID(as_uuid=True), nullable=True))
    op.add_column(
        "parsed_documents",
        sa.Column("source_id", UUID(as_uuid=True), sa.ForeignKey("source_records.id"), nullable=True),
    )
    op.add_column("parsed_documents", sa.Column("url", sa.Text(), nullable=True))
    op.add_column(
        "parsed_documents",
        sa.Column("content_type", sa.String(100), nullable=False, server_default="text/plain"),
    )
    op.add_column(
        "parsed_documents",
        sa.Column("word_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "parsed_documents",
        sa.Column("metadata", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.add_column(
        "parsed_documents",
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.add_column("parsed_documents", sa.Column("search_vector", postgresql.TSVECTOR(), nullable=True))
    op.create_index("ix_parsed_documents_tenant_url", "parsed_documents", ["tenant_id", "url"])
    op.create_index("ix_parsed_documents_source", "parsed_documents", ["source_id"])
    op.execute(
        "CREATE INDEX ix_parsed_documents_search_vector ON parsed_documents USING GIN(search_vector)"
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION parsed_documents_search_vector_update() RETURNS trigger AS $$
        BEGIN
            NEW.search_vector :=
                setweight(to_tsvector('english', coalesce(NEW.title, '')), 'A') ||
                setweight(to_tsvector('english', coalesce(NEW.url, '')), 'B') ||
                setweight(to_tsvector('english', coalesce(NEW.summary, '')), 'C');
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER parsed_documents_search_vector_trigger
        BEFORE INSERT OR UPDATE ON parsed_documents
        FOR EACH ROW EXECUTE FUNCTION parsed_documents_search_vector_update();
        """
    )

    # ------------------------------------------------------------------
    # document_sections — chunked text per article
    # ------------------------------------------------------------------
    op.alter_column("document_sections", "kind", nullable=True)
    op.add_column(
        "document_sections",
        sa.Column("section_index", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "document_sections",
        sa.Column("heading", sa.String(512), nullable=False, server_default=""),
    )
    # 0020 already added page_number, byte_offset_start, byte_offset_end — skip those.
    op.add_column(
        "document_sections",
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.add_column("document_sections", sa.Column("search_vector", postgresql.TSVECTOR(), nullable=True))
    op.execute(
        "CREATE INDEX ix_document_sections_search_vector ON document_sections USING GIN(search_vector)"
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION document_sections_search_vector_update() RETURNS trigger AS $$
        BEGIN
            NEW.search_vector :=
                setweight(to_tsvector('english', coalesce(NEW.heading, '')), 'A') ||
                setweight(to_tsvector('english', coalesce(NEW.content, '')), 'B');
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER document_sections_search_vector_trigger
        BEFORE INSERT OR UPDATE ON document_sections
        FOR EACH ROW EXECUTE FUNCTION document_sections_search_vector_update();
        """
    )

    # ------------------------------------------------------------------
    # evidence — citation rows linking entities/claims to documents
    # ------------------------------------------------------------------
    op.alter_column("evidence", "section_id", nullable=True)
    op.alter_column("evidence", "text_span", nullable=True)
    op.alter_column("evidence", "span_hash", nullable=True)
    op.add_column("evidence", sa.Column("tenant_id", UUID(as_uuid=True), nullable=True))
    op.add_column(
        "evidence",
        sa.Column("document_id", UUID(as_uuid=True), sa.ForeignKey("parsed_documents.id"), nullable=True),
    )
    op.add_column("evidence", sa.Column("claim_id", UUID(as_uuid=True), nullable=True))
    op.add_column("evidence", sa.Column("entity_id", UUID(as_uuid=True), nullable=True))
    op.add_column(
        "evidence",
        sa.Column("title", sa.String(512), nullable=False, server_default=""),
    )
    op.add_column("evidence", sa.Column("content", sa.Text(), nullable=False, server_default=""))
    op.add_column("evidence", sa.Column("text_snippet", sa.Text(), nullable=False, server_default=""))
    op.add_column("evidence", sa.Column("source_url", sa.Text(), nullable=True))
    op.add_column(
        "evidence",
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
    )
    # 0020 already added page_number, byte_offset_*, artifact_id — skip those.
    op.add_column(
        "evidence",
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_evidence_tenant", "evidence", ["tenant_id"])
    op.create_index("ix_evidence_document", "evidence", ["document_id"])
    op.create_index("ix_evidence_claim", "evidence", ["claim_id"])
    op.create_index("ix_evidence_entity", "evidence", ["entity_id"])


def downgrade() -> None:
    # Drop FTS triggers + indexes + columns added here.
    op.execute("DROP TRIGGER IF EXISTS document_sections_search_vector_trigger ON document_sections")
    op.execute("DROP FUNCTION IF EXISTS document_sections_search_vector_update()")
    op.execute("DROP INDEX IF EXISTS ix_document_sections_search_vector")
    op.execute("DROP TRIGGER IF EXISTS parsed_documents_search_vector_trigger ON parsed_documents")
    op.execute("DROP FUNCTION IF EXISTS parsed_documents_search_vector_update()")
    op.execute("DROP INDEX IF EXISTS ix_parsed_documents_search_vector")
    op.execute("DROP TRIGGER IF EXISTS source_records_url_hash_autofill ON source_records")
    op.execute("DROP FUNCTION IF EXISTS source_records_url_hash_trigger()")

    for col in ("tenant_id", "document_id", "claim_id", "entity_id", "title", "content",
                "text_snippet", "source_url", "confidence", "updated_at"):
        op.drop_column("evidence", col)
    op.alter_column("evidence", "span_hash", nullable=False)
    op.alter_column("evidence", "text_span", nullable=False)
    op.alter_column("evidence", "section_id", nullable=False)

    for col in ("section_index", "heading", "updated_at", "search_vector"):
        op.drop_column("document_sections", col)
    op.alter_column("document_sections", "kind", nullable=False)

    for col in ("tenant_id", "source_id", "url", "content_type", "word_count",
                "metadata", "updated_at", "search_vector"):
        op.drop_column("parsed_documents", col)
    op.alter_column("parsed_documents", "raw_object_id", nullable=False)

    for col in ("status", "error_message", "items_fetched", "duration_ms",
                "created_at", "updated_at"):
        op.drop_column("fetch_outcomes", col)
    op.alter_column("fetch_outcomes", "source_id", new_column_name="source_record_id")

    op.drop_index("ix_source_records_active_due", table_name="source_records")
    for col in ("source_type", "active", "last_fetched_at", "fetch_interval_seconds"):
        op.drop_column("source_records", col)
