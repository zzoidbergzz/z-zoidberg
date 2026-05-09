"""PDF report fetcher using pypdf."""

from __future__ import annotations
import logging
from pathlib import Path
from typing import Optional
import io

from .base import BaseFetcher

logger = logging.getLogger(__name__)


class PDFFetcher(BaseFetcher):
    """Fetches and extracts text from PDF reports."""

    def __init__(self, raw_store_path: str = "./raw_store/pdfs", **kwargs):
        super().__init__(**kwargs)
        self.raw_store_path = Path(raw_store_path)
        self.raw_store_path.mkdir(parents=True, exist_ok=True)

    async def fetch(self, source, max_items: int = 20) -> list[dict]:
        """Fetch and extract text from PDF reports."""
        items = []

        for endpoint in source.feeds_endpoints:
            if endpoint.type != "pdf" and not endpoint.url.endswith(".pdf"):
                continue

            resp = await self.fetch_url(endpoint.url, str(source.source_id))
            if resp is None:
                continue

            # Store raw PDF
            pdf_path = self._store_pdf(resp.content, endpoint.url, str(source.source_id))

            # Extract text
            text = self._extract_text(resp.content)
            if text:
                items.append({
                    "title": endpoint.description or Path(endpoint.url).stem,
                    "url": endpoint.url,
                    "body": text,
                    "published_at": None,
                    "author": source.source_name,
                    "tags": [],
                    "raw_pdf_path": str(pdf_path),
                })

        logger.info("Fetched %d PDF items from %s", len(items), source.source_name)
        return items[:max_items]

    def _store_pdf(self, content: bytes, url: str, source_id: str) -> Path:
        """Store raw PDF to filesystem."""
        import hashlib
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
        filename = f"{source_id}_{url_hash}.pdf"
        path = self.raw_store_path / filename
        path.write_bytes(content)
        logger.debug("Stored PDF: %s", path)
        return path

    @staticmethod
    def _extract_text(content: bytes) -> Optional[str]:
        """Extract text from PDF using pypdf."""
        try:
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(content))
            pages = []
            for page in reader.pages:
                text = page.extract_text()
                if text:
                    pages.append(text)
            return "\n\n".join(pages)
        except ImportError:
            logger.warning("pypdf not installed, skipping PDF extraction")
            return None
        except Exception as e:
            logger.warning("PDF text extraction failed: %s", e)
            return None
