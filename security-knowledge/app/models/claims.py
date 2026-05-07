import uuid
from sqlalchemy import String, Text, Float, Integer, ForeignKey, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.models.base import Base, TimestampMixin, UUIDMixin


class Claim(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "claims"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    document_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("parsed_documents.id"), nullable=True)
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    claim_type: Mapped[str] = mapped_column(String(100), nullable=False, default="general")
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    review_status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending")
    reviewer_notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    tags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    properties: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    versions: Mapped[list["ClaimVersion"]] = relationship("ClaimVersion", back_populates="claim")


class ClaimVersion(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "claim_versions"

    claim_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("claims.id"), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    changed_by: Mapped[str] = mapped_column(String(255), nullable=False, default="system")
    change_reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    claim: Mapped["Claim"] = relationship("Claim", back_populates="versions")
