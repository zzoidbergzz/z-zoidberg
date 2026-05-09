"""IOC Pingback models: watches, sightings, and SOC-to-SOC contacts."""
import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Text, UniqueConstraint, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from app.models.base import Base, UUIDMixin


class IocWatch(Base, UUIDMixin):
    """A user registers interest in an IOC value.

    mode='ping'    → anonymous sighting alerts only; seeker identity never revealed.
    mode='contact' → watcher also accepts SOC-to-SOC contact requests from seekers.
    """
    __tablename__ = "ioc_watches"
    __table_args__ = (
        UniqueConstraint("watchlist_id", "ioc_value_hash", "mode", name="uq_ioc_watch_list_ioc_mode"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    watchlist_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("watchlists.id", ondelete="CASCADE"), nullable=True, index=True)
    ioc_kind: Mapped[str] = mapped_column(String(50), nullable=False)
    ioc_value_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    ioc_value_display: Mapped[str] = mapped_column(String(512), nullable=False)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    mode: Mapped[str] = mapped_column(String(10), nullable=False, default="ping")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    contact_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    contact_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    notify_inbox: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    notify_email: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    notify_webhook: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Sighting counters (added in migration 0011)
    sighting_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_sighted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sector_context: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    sightings: Mapped[list["IocSighting"]] = relationship("IocSighting", back_populates="watch")
    watchlist: Mapped["Watchlist | None"] = relationship("Watchlist", back_populates="items")


class IocSighting(Base, UUIDMixin):
    """Recorded when a user (possibly in a different tenant) hits a watched IOC."""
    __tablename__ = "ioc_sightings"

    watch_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("ioc_watches.id", ondelete="CASCADE"), nullable=False)
    ioc_value_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    trigger: Mapped[str] = mapped_column(String(50), nullable=False, default="enrichment")
    seeker_tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    seeker_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    delivered: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Sector-sharing fields (added in migration 0011)
    seeker_sector: Mapped[str | None] = mapped_column(String(100), nullable=True)
    sector_share: Mapped[str] = mapped_column(String(10), nullable=False, default="limited")
    seeker_comment: Mapped[str | None] = mapped_column(Text, nullable=True)

    watch: Mapped["IocWatch"] = relationship("IocWatch", back_populates="sightings")
    contact: Mapped["IocContact | None"] = relationship("IocContact", back_populates="sighting", uselist=False)


class IocContact(Base, UUIDMixin):
    """SOC-to-SOC contact thread, created only for mode='contact' watches.

    Identity privacy:
    - Seeker sees: 'A watcher has been notified. Awaiting response.'
    - Watcher sees: 'A SOC team that observed [IOC] would like to connect.' (no seeker identity)
    - After acceptance: both parties' contact details are revealed simultaneously.
    """
    __tablename__ = "ioc_contacts"

    sighting_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("ioc_sightings.id", ondelete="CASCADE"), nullable=False)
    watch_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("ioc_watches.id", ondelete="CASCADE"), nullable=False)
    ioc_value_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    seeker_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    seeker_tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    watcher_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    seeker_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    watcher_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    seeker_revealed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    watcher_revealed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    sighting: Mapped["IocSighting"] = relationship("IocSighting", back_populates="contact")
