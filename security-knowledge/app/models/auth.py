import uuid
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Text, Enum, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.models.base import Base, TimestampMixin, UUIDMixin


class UserStatus(str, PyEnum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"


class UserRole(str, PyEnum):
    user = "user"
    admin = "admin"
    superadmin = "superadmin"


class Tenant(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    watchlist_settings: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    api_keys: Mapped[list["ApiKey"]] = relationship("ApiKey", back_populates="tenant")
    users: Mapped[list["User"]] = relationship("User", back_populates="tenant")


class ApiKey(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "api_keys"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    scopes: Mapped[str] = mapped_column(Text, default="read", nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="api_keys")


class User(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "users"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    business_sector: Mapped[str] = mapped_column(String(100), nullable=False, default="UK-General")
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Registration approval workflow
    status: Mapped[str] = mapped_column(String(20), default=UserStatus.pending, nullable=False)
    role: Mapped[str] = mapped_column(String(20), default=UserRole.user, nullable=False)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="users")
    provider_keys: Mapped[list["UserProviderKey"]] = relationship("UserProviderKey", back_populates="user")

    @property
    def is_admin(self) -> bool:
        return self.role in {UserRole.admin, UserRole.superadmin}

    @property
    def is_approved(self) -> bool:
        return self.status == UserStatus.approved


class UserProviderKey(Base, UUIDMixin, TimestampMixin):
    """Bring Your Own Key: user-supplied encrypted enrichment provider credentials.

    Security contract:
    - encrypted_key is Fernet-encrypted (AES-128-CBC + HMAC-SHA256) using BYOK_ENCRYPTION_KEY.
    - The plaintext key is NEVER returned by any API endpoint after initial write.
    - key_hint stores the last 4 characters so users can identify which key is stored ("...abcd").
    - Keys are decrypted server-side only, inline during enrichment, then immediately discarded.
    - All enrichment calls using a BYOK are logged in enrichment_usage with used_byok=true.
    - If BYOK_ENCRYPTION_KEY is rotated, existing keys will fail to decrypt gracefully (provider falls back to system key).
    """
    __tablename__ = "user_provider_keys"

    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    encrypted_key: Mapped[str] = mapped_column(Text, nullable=False)
    key_hint: Mapped[str | None] = mapped_column(String(10), nullable=True)
    user: Mapped["User"] = relationship("User", back_populates="provider_keys")


class TenantInviteRule(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "tenant_invite_rules"
    __table_args__ = (
        UniqueConstraint("tenant_id", "rule_type", "rule_value", name="uq_tenant_invite_rule"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    rule_type: Mapped[str] = mapped_column(String(20), nullable=False)  # email | domain
    rule_value: Mapped[str] = mapped_column(String(255), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
