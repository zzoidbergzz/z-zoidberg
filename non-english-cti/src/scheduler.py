"""Collection scheduler using APScheduler."""

from __future__ import annotations
import asyncio
import logging
from datetime import datetime
from typing import Optional

from .registry import SourceRegistry
from .fetchers.rss import RSSFetcher
from .fetchers.api import APIFetcher
from .fetchers.html import HTMLFetcher
from .models.record import CTIRecord, IOCSet
from .translation.detector import LanguageDetector
from .translation.translator import TranslationPipeline
from .translation.confidence import TranslationQA
from .extraction.ioc import extract_iocs
from .extraction.cve import extract_cves
from .extraction.ttp import extract_ttps, extract_actors, extract_malware
from .extraction.dedup import compute_content_hash, normalize_url, is_duplicate
from .storage.raw_store import RawEvidenceStore

logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    """Main orchestrator for the non-English CTI collection pipeline.

    Ties together: fetch → detect → translate → extract → dedup → score → store
    """

    def __init__(self, config: dict):
        self.config = config
        self.registry = SourceRegistry()

        fetch_config = config.get("fetching", {})
        self.rss_fetcher = RSSFetcher(
            user_agent=fetch_config.get("user_agent", RSSFetcher.DEFAULT_USER_AGENT),
            rate_limit=fetch_config.get("rate_limit_seconds", 2.0),
            timeout=fetch_config.get("request_timeout", 30.0),
        )
        self.api_fetcher = APIFetcher(
            user_agent=fetch_config.get("user_agent", RSSFetcher.DEFAULT_USER_AGENT),
            rate_limit=fetch_config.get("rate_limit_seconds", 2.0),
        )
        self.html_fetcher = HTMLFetcher(
            user_agent=fetch_config.get("user_agent", RSSFetcher.DEFAULT_USER_AGENT),
            rate_limit=fetch_config.get("rate_limit_seconds", 2.0),
        )

        self.detector = LanguageDetector()
        self.translator = TranslationPipeline(
            libretranslate_url=config.get("translation", {}).get("libretranslate_url", "http://localhost:5000"),
            deepl_api_key=config.get("translation", {}).get("deepl_api_key"),
        )
        self.translation_qa = TranslationQA()
        self.raw_store = RawEvidenceStore(
            base_path=config.get("storage", {}).get("raw_store_path", "./raw_store")
        )

        self.records: list[CTIRecord] = []
        self._seen_hashes: set[str] = set()

    def load_sources(self, catalogue_path: str) -> int:
        """Load source catalogue."""
        return self.registry.load(catalogue_path)

    async def run_collection_cycle(self, priority: int = 1) -> list[CTIRecord]:
        """Run one collection cycle for sources of given priority."""
        sources = self.registry.get_by_priority(priority)
        new_records = []

        for source in sources:
            try:
                items = await self._fetch_source(source)
                for item in items:
                    record = await self._process_item(item, source)
                    if record:
                        new_records.append(record)
                self.registry.mark_fetched(str(source.source_id))
            except Exception as e:
                logger.error("Collection error for %s: %s", source.source_name, e)
                self.registry.mark_fetched(str(source.source_id), error=str(e))

        logger.info("Collection cycle (priority %d): %d new records", priority, len(new_records))
        return new_records

    async def _fetch_source(self, source) -> list[dict]:
        """Fetch items from a source using the appropriate fetcher."""
        if source.collection_method == "rss":
            return await self.rss_fetcher.fetch(source)
        elif source.collection_method == "api":
            return await self.api_fetcher.fetch(source)
        elif source.collection_method == "html":
            return await self.html_fetcher.fetch(source)
        else:
            logger.warning("Unsupported collection method: %s", source.collection_method)
            return []

    async def _process_item(self, item: dict, source) -> Optional[CTIRecord]:
        """Process a raw item through the full pipeline."""
        title = item.get("title", "")
        body = item.get("body", "")
        url = item.get("url", "")

        if not title and not body:
            return None

        # 1. Language detection
        lang, lang_confidence = self.detector.detect(f"{title} {body}")
        if not lang:
            lang = source.language

        # 2. Translation (if not English)
        title_en = title
        body_en = body
        translation_method = "identity"
        translation_confidence = 1.0

        if lang != "en" and body:
            result = await self.translator.translate(body, lang, "en")
            body_en = result["translated_text"]
            translation_method = result["method"]
            translation_confidence = result["confidence"]

            # Also translate title
            title_result = await self.translator.translate(title, lang, "en")
            title_en = title_result["translated_text"]

        # 3. Build record
        record = CTIRecord(
            source_id=source.source_id,
            source_url=url,
            canonical_url=normalize_url(url) if url else None,
            title_original=title,
            title_en=title_en,
            body_original=body,
            body_en=body_en,
            language_detected=lang,
            country=source.country,
            region=source.region,
            source_type=source.source_type,
            published_at=item.get("published_at"),
            translation_method=translation_method,
            translation_confidence=translation_confidence,
        )

        # 4. Content hash and dedup
        record.hash_content = compute_content_hash(title, body)
        if record.hash_content in self._seen_hashes:
            return None
        self._seen_hashes.add(record.hash_content)

        # 5. IOC extraction
        if self.config.get("extraction", {}).get("ioc_extraction", True):
            text_for_extraction = f"{title} {body}"
            record.extracted_iocs = extract_iocs(text_for_extraction)

        # 6. CVE extraction
        if self.config.get("extraction", {}).get("cve_extraction", True):
            record.extracted_cves = extract_cves(f"{title} {body}")

        # 7. TTP mapping
        if self.config.get("extraction", {}).get("ttp_mapping", True):
            record.extracted_ttps = extract_ttps(f"{title} {body}")

        # 8. Actor and malware extraction
        record.extracted_actors = extract_actors(f"{title} {body}")
        record.extracted_malware = extract_malware(f"{title} {body}")

        # 9. Scoring
        scoring_config = self.config.get("scoring", {})
        source_type_rel = scoring_config.get("source_type_reliability", {}).get(source.source_type, 0.5)
        record.reliability_score = source_type_rel
        record.confidence_score = (
            translation_confidence * scoring_config.get("translation_confidence_weight", 0.3)
            + source_type_rel * scoring_config.get("source_reliability_weight", 0.4)
            + (0.5 if record.extracted_iocs and (record.extracted_iocs.ipv4 or record.extracted_iocs.domains or record.extracted_iocs.sha256_hashes) else 0.0)
        )
        record.confidence_score = min(record.confidence_score, 1.0)

        # 10. Translation QA
        if lang != "en" and body_en:
            qa_result = self.translation_qa.score_translation(body, body_en, lang)
            if qa_result["flags"]:
                logger.debug("Translation QA flags for %s: %s", url, qa_result["flags"])

        # 11. Analyst status — require review for high-impact items
        review_config = self.config.get("review", {}).get("mandatory_review_thresholds", {})
        if review_config.get("actor_attribution") and record.extracted_actors:
            record.analyst_status = "new"  # Will be queued for review
        if review_config.get("victim_claim") and record.extracted_victims:
            record.analyst_status = "new"

        return record

    async def close(self):
        """Close all fetcher clients."""
        await self.rss_fetcher.close()
        await self.api_fetcher.close()
        await self.html_fetcher.close()
