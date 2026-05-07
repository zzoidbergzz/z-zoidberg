import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Text, Integer, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.models.base import Base, TimestampMixin, UUIDMixin


class SourceRecord(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "sources"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    kind: Mapped[str] = mapped_column(String(50), nullable=False, default="feed")
    source_type: Mapped[str] = mapped_column(String(50), nullable=False, default="generic")
    policy_status: Mapped[str] = mapped_column(String(50), nullable=False, default="allowed")
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    external_refs: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    last_fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fetch_interval_seconds: Mapped[int] = mapped_column(Integer, default=3600, nullable=False)


class FetchOutcome(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "fetch_outcomes"

    source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("sources.id"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    items_fetched: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class RawObject(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "raw_objects"

    source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("sources.id"), nullable=False, index=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    raw_content: Mapped[str] = mapped_column(Text, nullable=False)
    content_type: Mapped[str] = mapped_column(String(100), nullable=False, default="text/plain")
    processed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
