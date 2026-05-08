"""CorpusDocument model — historical security corpus records."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDMixin


class CorpusDocument(Base, UUIDMixin, TimestampMixin):
    """A record from one of the historical security corpora (CVE, GCVE, ExploitDB)."""

    __tablename__ = "corpus_documents"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )
    corpus: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # 'cve' | 'gcve' | 'exploitdb'
    external_id: Mapped[str] = mapped_column(
        Text, nullable=False, index=True
    )  # e.g. CVE-2024-1234, EDB-50000
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    body_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    source_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    modified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    search_vector: Mapped[str | None] = mapped_column(TSVECTOR, nullable=True)

    __table_args__ = (
        UniqueConstraint("corpus", "external_id", name="uq_corpus_external_id"),
        Index("ix_corpus_documents_search_vector", "search_vector", postgresql_using="gin"),
    )
