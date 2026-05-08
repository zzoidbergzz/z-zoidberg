import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDMixin


class SourceRecord(Base, UUIDMixin, TimestampMixin):
    # Table is named ``source_records`` in the live DB (legacy from migration
    # 0003). Columns ``url_hash`` (auto-filled by trigger) and ``search_vector``
    # exist on the table but are not modelled here — Postgres-managed.
    __tablename__ = "source_records"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str | None] = mapped_column(String(1024), nullable=True, default="")
    kind: Mapped[str] = mapped_column(String(50), nullable=False, default="feed")
    source_type: Mapped[str] = mapped_column(String(50), nullable=False, default="generic")
    policy_status: Mapped[str] = mapped_column(String(50), nullable=False, default="allowed")
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    external_refs: Mapped[dict] = mapped_column(JSONB, nullable=True, default=dict)
    last_fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fetch_interval_seconds: Mapped[int] = mapped_column(Integer, default=3600, nullable=False)


class FetchOutcome(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "fetch_outcomes"

    source_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("source_records.id"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="ok")
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    items_fetched: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class RawObject(Base, UUIDMixin):
    # The live DB ``raw_objects`` table stores blob references (storage_path,
    # content_hash, size_bytes) and is keyed by ``source_record_id``. The
    # ingestion worker writes plaintext into ``parsed_documents`` directly
    # rather than persisting raw HTML, so this model is read-only scaffolding
    # kept in-sync with the actual columns to avoid query crashes.
    __tablename__ = "raw_objects"

    source_record_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("source_records.id"), nullable=False, index=True
    )
    storage_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    content_type: Mapped[str] = mapped_column(String(100), nullable=False, default="text/plain")
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
