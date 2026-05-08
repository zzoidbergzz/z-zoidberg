import uuid
import enum
from sqlalchemy import String, Text, ForeignKey, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.models.base import Base, TimestampMixin, UUIDMixin


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
    aliases: Mapped[list["EntityAlias"]] = relationship("EntityAlias", back_populates="entity")


class EntityAlias(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "entity_aliases"

    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("entities.id"), nullable=False, index=True)
    alias: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    entity: Mapped["Entity"] = relationship("Entity", back_populates="aliases")
