"""Core domain tables

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-07
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

_TENANT_ID = sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)


def upgrade() -> None:
    op.create_table(
        "source_records",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("url_hash", sa.String(64), nullable=False),
        sa.Column("title", sa.String(1024), nullable=True),
        sa.Column("kind", sa.String(50), nullable=False, server_default="generic"),
        sa.Column("policy_status", sa.String(20), nullable=False, server_default="unknown"),
        sa.Column("external_refs", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_source_records_tenant_id", "source_records", ["tenant_id"])
    op.create_index("ix_source_records_url_hash", "source_records", ["url_hash"])

    op.create_table(
        "fetch_outcomes",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("source_record_id", UUID(as_uuid=True), sa.ForeignKey("source_records.id", ondelete="CASCADE"), nullable=False),
        sa.Column("http_status", sa.Integer, nullable=True),
        sa.Column("blocked_reason", sa.String(255), nullable=True),
        sa.Column("raw_size", sa.BigInteger, nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "raw_objects",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("source_record_id", UUID(as_uuid=True), sa.ForeignKey("source_records.id", ondelete="CASCADE"), nullable=False),
        sa.Column("storage_path", sa.Text, nullable=True),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("content_type", sa.String(100), nullable=True),
        sa.Column("size_bytes", sa.BigInteger, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "parsed_documents",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("raw_object_id", UUID(as_uuid=True), sa.ForeignKey("raw_objects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("format", sa.String(50), nullable=False, server_default="html"),
        sa.Column("title", sa.String(1024), nullable=True),
        sa.Column("summary", sa.Text, nullable=True),
        sa.Column("sections_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "document_sections",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("document_id", UUID(as_uuid=True), sa.ForeignKey("parsed_documents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(50), nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("order_idx", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "evidence",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("section_id", UUID(as_uuid=True), sa.ForeignKey("document_sections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("text_span", sa.Text, nullable=False),
        sa.Column("span_hash", sa.String(64), nullable=False),
        sa.Column("start_char", sa.Integer, nullable=True),
        sa.Column("end_char", sa.Integer, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_evidence_span_hash", "evidence", ["span_hash"])

    op.create_table(
        "chunk_embeddings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("evidence_id", UUID(as_uuid=True), sa.ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False),
        sa.Column("model", sa.String(100), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    # pgvector column added separately to handle optional extension
    op.execute("ALTER TABLE chunk_embeddings ADD COLUMN IF NOT EXISTS vector vector(1536)")

    op.create_table(
        "entities",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(50), nullable=False),
        sa.Column("canonical_name", sa.String(512), nullable=False),
        sa.Column("aliases", JSONB, nullable=True),
        sa.Column("external_refs", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_entities_tenant_id", "entities", ["tenant_id"])
    op.create_index("ix_entities_kind", "entities", ["kind"])

    op.create_table(
        "claims",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("entity_id", UUID(as_uuid=True), sa.ForeignKey("entities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("evidence_id", UUID(as_uuid=True), sa.ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True),
        sa.Column("claim_type", sa.String(100), nullable=False),
        sa.Column("value", JSONB, nullable=False),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.5"),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("external_refs", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_claims_tenant_id", "claims", ["tenant_id"])
    op.create_index("ix_claims_entity_id", "claims", ["entity_id"])

    op.create_table(
        "relationships",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("from_entity_id", UUID(as_uuid=True), sa.ForeignKey("entities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("to_entity_id", UUID(as_uuid=True), sa.ForeignKey("entities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(50), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.5"),
        sa.Column("claim_id", UUID(as_uuid=True), sa.ForeignKey("claims.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_relationships_tenant_id", "relationships", ["tenant_id"])
    op.create_index("ix_relationships_from_entity_id", "relationships", ["from_entity_id"])

    op.create_table(
        "ingestion_jobs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("source_url", sa.Text, nullable=True),
        sa.Column("source_type", sa.String(50), nullable=False, server_default="generic"),
        sa.Column("priority", sa.Integer, nullable=False, server_default="5"),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("progress_pct", sa.Integer, nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_ingestion_jobs_tenant_id", "ingestion_jobs", ["tenant_id"])
    op.create_index("ix_ingestion_jobs_status", "ingestion_jobs", ["status"])

    op.create_table(
        "audit_events",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("actor_id", sa.String(255), nullable=True),
        sa.Column("actor_kind", sa.String(50), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource_kind", sa.String(100), nullable=True),
        sa.Column("resource_id", sa.String(255), nullable=True),
        sa.Column("details", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_audit_events_tenant_id", "audit_events", ["tenant_id"])
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("ingestion_jobs")
    op.drop_table("relationships")
    op.drop_table("claims")
    op.drop_table("entities")
    op.drop_table("chunk_embeddings")
    op.drop_table("evidence")
    op.drop_table("document_sections")
    op.drop_table("parsed_documents")
    op.drop_table("raw_objects")
    op.drop_table("fetch_outcomes")
    op.drop_table("source_records")
