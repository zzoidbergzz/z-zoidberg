import uuid

from sqlalchemy import String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDMixin


class LearningUnit(Base, UUIDMixin, TimestampMixin):
    """Structured learning unit from the security knowledge research pack."""

    __tablename__ = "learning_units"
    __table_args__ = (UniqueConstraint("tenant_id", "learning_unit_id", name="uq_learning_units_tenant_lu_id"),)

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    learning_unit_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    level: Mapped[str] = mapped_column(String(64), nullable=False, default="foundation")
    roles: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    domains: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    objectives: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    prerequisites: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    source_refs: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    entity_refs: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    fact_refs: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    lab: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    assessment: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    retrieval_tags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
