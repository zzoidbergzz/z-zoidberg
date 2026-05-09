"""MCP tool: collect non-English CTI from prioritized sources."""

from __future__ import annotations

import asyncio
import structlog

from app.mcp.registry import register_tool

logger = structlog.get_logger(__name__)


async def _necti_collect(args: dict, db, auth) -> dict:
    priority = int(args.get("priority", 1))
    max_items = int(args.get("max_items", 10))
    source_name = args.get("source_name")

    # Lazy import to avoid circular deps / startup cost
    import sys
    from pathlib import Path
    necti_path = Path.home() / "non-english-cti"
    if str(necti_path) not in sys.path:
        sys.path.insert(0, str(necti_path))

    from src.registry import SourceRegistry
    from src.fetchers.rss import RSSFetcher
    from src.translation.detector import LanguageDetector
    from src.translation.translator import TranslationPipeline
    from src.extraction.ioc import extract_iocs
    from src.extraction.cve import extract_cves

    registry = SourceRegistry()
    catalogue = str(necti_path / "catalogue" / "sources.yaml")
    registry.load(catalogue)

    if source_name:
        sources = [registry.get_by_name(source_name)]
        sources = [s for s in sources if s]
    else:
        sources = registry.get_by_priority(priority)

    if not sources:
        return {"error": "no_sources_found", "message": f"No sources for priority {priority}"}

    fetcher = RSSFetcher(rate_limit=2.0, timeout=15.0)
    detector = LanguageDetector()
    translator = TranslationPipeline(libretranslate_url="http://localhost:5000")

    collected = []

    for source in sources[:3]:  # Limit to 3 sources per call
        try:
            items = await fetcher.fetch(source)
            for item in items[:max_items]:
                title = item.get("title", "")
                body = item.get("body", "")[:500]
                url = item.get("url", "")

                lang, conf = detector.detect(title) if title else (source.language, 0.0)
                title_en = title

                if lang != "en" and title:
                    result = await translator.translate(title, lang, "en")
                    title_en = result.get("translated_text", title)

                entry = {
                    "source": source.source_name,
                    "language": lang,
                    "title_original": title[:100],
                    "title_en": title_en[:100],
                    "url": url,
                }

                if body:
                    iocs = extract_iocs(body)
                    cves = extract_cves(body)
                    if iocs.ipv4 or iocs.domains:
                        entry["iocs"] = {
                            "ipv4": iocs.ipv4 or [],
                            "domains": iocs.domains or [],
                        }
                    if cves:
                        entry["cves"] = cves

                collected.append(entry)
        except Exception as exc:
            logger.warning("necti_source_error", source=source.source_name, error=str(exc))

    await fetcher.close()

    return {
        "collected": len(collected),
        "sources_queried": len(sources[:3]),
        "items": collected,
    }


register_tool(
    name="necti_collect",
    fn=_necti_collect,
    schema={
        "type": "object",
        "properties": {
            "priority": {"type": "integer", "description": "Source priority level 1-4 (default 1)"},
            "max_items": {"type": "integer", "description": "Max items per source (default 10)"},
            "source_name": {"type": "string", "description": "Specific source name to collect from"},
        },
    },
    description="Collect and translate non-English cyber threat intelligence from prioritized sources. Returns translated advisories with extracted IOCs and CVEs.",
    scope="read",
)
