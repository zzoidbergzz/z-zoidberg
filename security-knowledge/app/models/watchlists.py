"""Watchlist collections and watch items."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin


class Watchlist(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "watchlists"
    __table_args__ = (
        UniqueConstraint("tenant_id", "scope", "owner_user_id", "name", name="uq_watchlists_tenant_scope_owner_name"),
        UniqueConstraint("public_slug", name="uq_watchlists_public_slug"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scope: Mapped[str] = mapped_column(String(20), nullable=False, default="personal")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    expiry_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=12960)
    export_formats: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    public_slug: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    allow_unauthenticated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    items: Mapped[list["IocWatch"]] = relationship("IocWatch", back_populates="watchlist")

    @property
    def is_org(self) -> bool:
        return self.scope == "org"


class WatchlistExportToken(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "watchlist_export_tokens"

    watchlist_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("watchlists.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    formats: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    watchlist: Mapped["Watchlist"] = relationship("Watchlist")
