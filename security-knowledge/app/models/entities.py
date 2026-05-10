import uuid
import enum
from sqlalchemy import String, Text, ForeignKey, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.models.base import Base, TimestampMixin, UUIDMixin

try:
    from pgvector.sqlalchemy import Vector as _Vector
    _VECTOR_TYPE = _Vector(1536)
except ImportError:  # pgvector not installed in this env
    _Vector = None  # type: ignore[assignment,misc]
    _VECTOR_TYPE = None  # type: ignore[assignment]


class EntityKind(str, enum.Enum):
    vulnerability = "vulnerability"
    actor = "actor"
    malware = "malware"
    product = "product"
    ip_address = "ip_address"
    domain = "domain"
    hash = "hash"
    url = "url"
    email = "email"
    cve = "cve"
    cwe = "cwe"
    organization = "organization"
    asn = "asn"
    indicator = "indicator"
    tool = "tool"
    campaign = "campaign"
    attack_pattern = "attack_pattern"
    course_of_action = "course_of_action"
    report = "report"
    other = "other"


class Entity(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "entities"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    canonical_name: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    mitre_attack_id: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    external_refs: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # pgvector embedding — nullable; populated asynchronously by the embedding ARQ worker.
    # Only present when the pgvector extension is installed (migration 0037).
    embedding: Mapped[list[float] | None] = mapped_column(
        _VECTOR_TYPE, nullable=True  # type: ignore[arg-type]
    ) if _VECTOR_TYPE is not None else mapped_column(Text, nullable=True)
    aliases: Mapped[list["EntityAlias"]] = relationship("EntityAlias", back_populates="entity")


class EntityAlias(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "entity_aliases"

    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("entities.id"), nullable=False, index=True)
    alias: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    entity: Mapped["Entity"] = relationship("Entity", back_populates="aliases")
