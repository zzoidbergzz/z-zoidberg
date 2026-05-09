"""Source registry — loads and validates source catalogue from YAML."""

from __future__ import annotations
import logging
from pathlib import Path
from typing import Optional

import yaml
from .models.record import Source

logger = logging.getLogger(__name__)


class SourceRegistry:
    """Manages the source catalogue: load, query, health check."""

    def __init__(self, catalogue_path: Optional[str | Path] = None):
        self.sources: dict[str, Source] = {}
        if catalogue_path:
            self.load(catalogue_path)

    def load(self, path: str | Path) -> int:
        """Load sources from YAML file. Returns count of loaded sources."""
        path = Path(path)
        if not path.exists():
            logger.error("Source catalogue not found: %s", path)
            return 0

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data:
            logger.warning("Empty source catalogue: %s", path)
            return 0

        count = 0
        for entry in data:
            if not isinstance(entry, dict) or "source_name" not in entry:
                continue
            try:
                source = Source(**entry)
                self.sources[str(source.source_id)] = source
                count += 1
            except Exception as e:
                logger.warning("Skipping invalid source %s: %s", entry.get("source_name", "?"), e)

        logger.info("Loaded %d sources from %s", count, path)
        return count

    def get_by_name(self, name: str) -> Optional[Source]:
        """Find a source by name."""
        for s in self.sources.values():
            if s.source_name == name:
                return s
        return None

    def get_by_language(self, language: str) -> list[Source]:
        """Get all sources for a given language (ISO 639-1)."""
        return [s for s in self.sources.values() if s.language == language and s.enabled]

    def get_by_type(self, source_type: str) -> list[Source]:
        """Get all sources of a given type."""
        return [s for s in self.sources.values() if s.source_type == source_type and s.enabled]

    def get_by_priority(self, priority: int) -> list[Source]:
        """Get all sources with a given collection priority."""
        return [s for s in self.sources.values() if s.collection_priority == priority and s.enabled]

    def get_by_method(self, method: str) -> list[Source]:
        """Get all sources with a given collection method."""
        return [s for s in self.sources.values() if s.collection_method == method and s.enabled]

    def get_enabled(self) -> list[Source]:
        """Get all enabled sources."""
        return [s for s in self.sources.values() if s.enabled]

    def get_rss_sources(self) -> list[Source]:
        """Get all sources with RSS feeds (primary collection method)."""
        sources = []
        for s in self.sources.values():
            if not s.enabled:
                continue
            if s.collection_method == "rss":
                sources.append(s)
            elif any(ep.type == "rss" for ep in s.feeds_endpoints):
                sources.append(s)
        return sources

    def get_api_sources(self) -> list[Source]:
        """Get all sources with API access."""
        sources = []
        for s in self.sources.values():
            if not s.enabled:
                continue
            if s.collection_method == "api":
                sources.append(s)
            elif any(ep.type == "api" for ep in s.feeds_endpoints):
                sources.append(s)
        return sources

    def mark_fetched(self, source_id: str, error: Optional[str] = None) -> None:
        """Update source fetch status."""
        source = self.sources.get(source_id)
        if source:
            source.last_fetched = __import__("datetime").datetime.utcnow()
            if error:
                source.last_error = error
                source.consecutive_failures += 1
            else:
                source.last_error = None
                source.consecutive_failures = 0

    def summary(self) -> dict:
        """Return summary statistics."""
        enabled = [s for s in self.sources.values() if s.enabled]
        return {
            "total": len(self.sources),
            "enabled": len(enabled),
            "by_language": {lang: len([s for s in enabled if s.language == lang]) for lang in set(s.language for s in enabled)},
            "by_type": {t: len([s for s in enabled if s.source_type == t]) for t in set(s.source_type for s in enabled)},
            "by_priority": {p: len([s for s in enabled if s.collection_priority == p]) for p in set(s.collection_priority for s in enabled)},
        }
