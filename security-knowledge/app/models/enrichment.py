import uuid
from datetime import datetime
from sqlalchemy import String, Text, Boolean, Integer, DateTime, Float, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.models.base import Base, TimestampMixin, UUIDMixin


class EnrichmentCache(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "enrichment_cache"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    entity_kind: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    raw_response: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    normalized: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    success: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)


class EnrichmentUsage(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "enrichment_usage"

    provider: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    date: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    budget: Mapped[int] = mapped_column(Integer, nullable=False, default=1000)


class EnrichmentDiff(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "enrichment_diffs"

    cache_entry_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("enrichment_cache.id", ondelete="SET NULL"), nullable=True)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_kind: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_value: Mapped[str] = mapped_column(String(512), nullable=False)
    previous_normalized: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    new_normalized: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    diff_summary: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    has_changes: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    requested_by_tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
