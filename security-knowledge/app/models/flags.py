import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDMixin


class FlaggedItem(Base, UUIDMixin, TimestampMixin):
    """A feed item flagged by a user for follow-up."""
    __tablename__ = "flagged_items"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # trend, news, breach
    title: Mapped[str] = mapped_column(String(1024), nullable=False)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    external_id: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)  # dedup key
    flagged_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    acked_by: Mapped[str | None] = mapped_column(String(256), nullable=True)  # user email or "anonymous"
    acked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
