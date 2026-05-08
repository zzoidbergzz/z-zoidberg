import uuid

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin


class ParsedDocument(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "parsed_documents"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    source_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("sources.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_type: Mapped[str] = mapped_column(String(100), nullable=False, default="text/plain")
    word_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    sections: Mapped[list["DocumentSection"]] = relationship("DocumentSection", back_populates="document")


class DocumentSection(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "document_sections"

    document_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("parsed_documents.id"), nullable=False, index=True
    )
    section_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    heading: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    content: Mapped[str] = mapped_column(Text, nullable=False)
    page_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    byte_offset_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    byte_offset_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    document: Mapped["ParsedDocument"] = relationship("ParsedDocument", back_populates="sections")
