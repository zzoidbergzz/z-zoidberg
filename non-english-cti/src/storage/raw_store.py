"""Raw evidence store — filesystem storage for HTML, PDF, JSON."""

from __future__ import annotations
import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class RawEvidenceStore:
    """Stores raw collected content (HTML, PDF, JSON) on filesystem.

    Structure:
        raw_store/
        ├── html/
        │   ├── {source_id}/
        │   │   └── {url_hash}.html
        ├── pdf/
        │   └── {source_id}/
        │       └── {url_hash}.pdf
        ├── json/
        │   └── {source_id}/
        │       └── {url_hash}.json
        └── metadata/
            └── {source_id}/
                └── {url_hash}.meta.json
    """

    def __init__(self, base_path: str = "./raw_store"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)

    def store_html(self, source_id: str, url: str, content: str, metadata: Optional[dict] = None) -> str:
        """Store raw HTML content. Returns path to stored file."""
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
        dir_path = self.base_path / "html" / source_id
        dir_path.mkdir(parents=True, exist_ok=True)
        file_path = dir_path / f"{url_hash}.html"
        file_path.write_text(content, encoding="utf-8")

        if metadata:
            self._store_metadata(source_id, url_hash, metadata)

        return str(file_path)

    def store_pdf(self, source_id: str, url: str, content: bytes, metadata: Optional[dict] = None) -> str:
        """Store raw PDF content. Returns path to stored file."""
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
        dir_path = self.base_path / "pdf" / source_id
        dir_path.mkdir(parents=True, exist_ok=True)
        file_path = dir_path / f"{url_hash}.pdf"
        file_path.write_bytes(content)

        if metadata:
            self._store_metadata(source_id, url_hash, metadata)

        return str(file_path)

    def store_json(self, source_id: str, url: str, data: dict, metadata: Optional[dict] = None) -> str:
        """Store raw JSON data. Returns path to stored file."""
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
        dir_path = self.base_path / "json" / source_id
        dir_path.mkdir(parents=True, exist_ok=True)
        file_path = dir_path / f"{url_hash}.json"
        file_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

        if metadata:
            self._store_metadata(source_id, url_hash, metadata)

        return str(file_path)

    def _store_metadata(self, source_id: str, url_hash: str, metadata: dict) -> None:
        """Store collection metadata."""
        dir_path = self.base_path / "metadata" / source_id
        dir_path.mkdir(parents=True, exist_ok=True)
        file_path = dir_path / f"{url_hash}.meta.json"
        metadata["stored_at"] = datetime.utcnow().isoformat()
        file_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")

    def get_html(self, path: str) -> Optional[str]:
        """Read stored HTML content."""
        file_path = Path(path)
        if file_path.exists():
            return file_path.read_text(encoding="utf-8")
        return None
