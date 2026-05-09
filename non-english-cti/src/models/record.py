"""Pydantic models for the non-English CTI pipeline."""

from __future__ import annotations
import hashlib
from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4
from typing import Optional

from pydantic import BaseModel, Field, HttpUrl


class SourceType(str, Enum):
    CERT = "cert"
    VULNDB = "vulndb"
    VENDOR = "vendor"
    SOCIAL = "social"
    NEWS = "news"


class CollectionMethod(str, Enum):
    RSS = "rss"
    API = "api"
    HTML = "html"
    SITEMAP = "sitemap"
    PDF = "pdf"
    SOCIAL = "social"
    MANUAL = "manual"


class AuthRequirement(str, Enum):
    NONE = "none"
    API_KEY = "api_key"
    LOGIN = "login"
    UNKNOWN = "unknown"


class AnalystStatus(str, Enum):
    NEW = "new"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"


class FeedEndpoint(BaseModel):
    type: str
    url: str
    description: str = ""


class Source(BaseModel):
    """Source metadata for a CTI feed."""
    source_id: UUID = Field(default_factory=uuid4)
    source_name: str
    url: str
    country: str  # ISO 3166-1 alpha-2
    region: str
    language: str  # ISO 639-1
    source_type: SourceType
    collection_method: CollectionMethod
    authentication: AuthRequirement = AuthRequirement.NONE
    update_frequency: str = "weekly"
    intelligence_value: int = Field(ge=1, le=5, default=3)
    reliability: int = Field(ge=1, le=5, default=3)
    legal_ethical_risk: int = Field(ge=1, le=5, default=1)
    collection_priority: int = Field(ge=1, le=4, default=3)
    notes: str = ""
    tos_robots_rate: str = ""
    example_intelligence: str = ""
    feeds_endpoints: list[FeedEndpoint] = []
    enabled: bool = True
    last_fetched: Optional[datetime] = None
    last_error: Optional[str] = None
    consecutive_failures: int = 0


class IOCSet(BaseModel):
    """Extracted indicators of compromise."""
    ipv4: list[str] = []
    ipv6: list[str] = []
    domains: list[str] = []
    urls: list[str] = []
    email_addresses: list[str] = []
    md5_hashes: list[str] = []
    sha1_hashes: list[str] = []
    sha256_hashes: list[str] = []
    file_names: list[str] = []
    c2_servers: list[str] = []


class CTIRecord(BaseModel):
    """Normalised CTI record with original and translated content."""
    record_id: UUID = Field(default_factory=uuid4)
    source_id: UUID
    source_url: str
    canonical_url: Optional[str] = None
    title_original: str
    title_en: Optional[str] = None
    body_original: str
    body_en: Optional[str] = None
    language_detected: str = ""
    country: str = ""
    region: str = ""
    source_type: str = ""
    published_at: Optional[datetime] = None
    collected_at: datetime = Field(default_factory=datetime.utcnow)
    hash_content: str = ""
    extracted_iocs: Optional[IOCSet] = None
    extracted_cves: list[str] = []
    extracted_ttps: list[dict] = []
    extracted_actors: list[str] = []
    extracted_malware: list[str] = []
    extracted_tools: list[str] = []
    extracted_victims: list[str] = []
    sectors: list[str] = []
    confidence_score: float = 0.0
    reliability_score: float = 0.0
    analyst_status: AnalystStatus = AnalystStatus.NEW
    export_status: dict = {}
    citations: list[dict] = []
    translation_method: Optional[str] = None
    translation_confidence: Optional[float] = None
    raw_html_path: Optional[str] = None
    raw_pdf_path: Optional[str] = None
    tags: list[str] = []

    def compute_hash(self) -> str:
        """Compute SHA-256 content hash from original title + body."""
        content = f"{self.title_original}\n{self.body_original}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def mark_reviewed(self, status: AnalystStatus, reviewer: str = "") -> None:
        """Update analyst status."""
        self.analyst_status = status
