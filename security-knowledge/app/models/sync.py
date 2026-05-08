import uuid
from datetime import datetime
from sqlalchemy import String, Text, Boolean, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.models.base import Base, TimestampMixin, UUIDMixin


class SyncState(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "sync_states"

    integration: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cursor: Mapped[str | None] = mapped_column(Text, nullable=True)
    state: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class TaxiiCollection(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "taxii_collections"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    collection_id: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    can_read: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    can_write: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    alias: Mapped[str | None] = mapped_column(String(255), nullable=True)
