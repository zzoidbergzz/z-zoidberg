import uuid
from datetime import datetime
from sqlalchemy import String, Text, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.models.base import Base, TimestampMixin, UUIDMixin


class GraphCache(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "graph_cache"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    cache_key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    graph_data: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    format: Mapped[str] = mapped_column(String(50), nullable=False, default="vis")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
