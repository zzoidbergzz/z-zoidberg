"""Sector / ISAC group models."""
import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, Integer, DateTime, ForeignKey, UniqueConstraint, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from app.models.base import Base, TimestampMixin, UUIDMixin


class Sector(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "sectors"

    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    isac_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    info_sharing_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    member_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class SectorMembership(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "sector_memberships"
    __table_args__ = (
        UniqueConstraint("sector_id", "user_id", name="uq_sector_membership"),
    )

    sector_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("sectors.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    org_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    invited_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)


class SectorInvite(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "sector_invites"

    sector_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("sectors.id", ondelete="CASCADE"), nullable=False)
    invited_email: Mapped[str] = mapped_column(String(255), nullable=False)
    invited_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
