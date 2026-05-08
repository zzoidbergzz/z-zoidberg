import uuid
from datetime import datetime
from sqlalchemy import String, Text, Boolean, DateTime, Integer
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.models.base import Base, TimestampMixin, UUIDMixin
from typing import Optional


class SavedSearch(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "saved_searches"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    query: Mapped[str] = mapped_column(Text, nullable=False)
    filters: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="system")
    public: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class DigestSubscription(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "digest_subscriptions"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    schedule: Mapped[str] = mapped_column(String(100), nullable=False, default="0 8 * * *")
    frequency: Mapped[str] = mapped_column(String(50), nullable=False, default="daily")
    channels: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    filters: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    template: Mapped[str] = mapped_column(Text, nullable=False, default="")
    next_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class DigestRun(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "digest_runs"

    subscription_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending")
    item_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    items_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False, default="")


class InboxItem(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "inbox_items"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    subject: Mapped[str] = mapped_column(String(512), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    source_type: Mapped[str] = mapped_column(String(100), nullable=False, default="digest")
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)
