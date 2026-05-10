"""EUVD (EU Vulnerability Database) API client.

Base URL: https://euvdservices.enisa.europa.eu/api
No authentication required. Rate-limited: 1 req/sec between pages.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

BASE_URL = "https://euvdservices.enisa.europa.eu/api"


@dataclass
class EUVDProduct:
    id: str
    name: str
    product_version: str | None = None


@dataclass
class EUVDVendor:
    id: str
    name: str


@dataclass
class EUVDRecord:
    id: str  # EUVD-YYYY-#####
    description: str
    date_published: str  # Raw format: "Apr 15, 2025, 8:30:58 PM"
    date_updated: str
    base_score: float | None = None
    base_score_version: str | None = None
    base_score_vector: str | None = None
    references: list[str] = field(default_factory=list)  # URLs
    aliases: list[str] = field(default_factory=list)  # CVE-*, GSD-*
    assigner: str | None = None
    epss: float | None = None  # 0.0 - 1.0
    products: list[EUVDProduct] = field(default_factory=list)
    vendors: list[EUVDVendor] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class EUVDSearchResult:
    items: list[EUVDRecord]
    total: int
    page: int
    size: int


def _parse_products(data: list[dict]) -> list[EUVDProduct]:
    result = []
    for p in data:
        prod = p.get("product", {})
        result.append(EUVDProduct(
            id=p.get("id", ""),
            name=prod.get("name", ""),
            product_version=p.get("product_version"),
        ))
    return result


def _parse_vendors(data: list[dict]) -> list[EUVDVendor]:
    result = []
    for v in data:
        vend = v.get("vendor", {})
        result.append(EUVDVendor(
            id=v.get("id", ""),
            name=vend.get("name", ""),
        ))
    return result


def _parse_record(item: dict[str, Any]) -> EUVDRecord:
    refs_raw = item.get("references", "")
    refs = [r.strip() for r in refs_raw.split("\n") if r.strip()] if refs_raw else []

    aliases_raw = item.get("aliases", "")
    aliases = [a.strip().lstrip("\\") for a in aliases_raw.split("\n") if a.strip()] if aliases_raw else []

    return EUVDRecord(
        id=item.get("id", ""),
        description=item.get("description", ""),
        date_published=item.get("datePublished", ""),
        date_updated=item.get("dateUpdated", ""),
        base_score=item.get("baseScore"),
        base_score_version=item.get("baseScoreVersion"),
        base_score_vector=item.get("baseScoreVector"),
        references=refs,
        aliases=aliases,
        assigner=item.get("assigner"),
        epss=item.get("epss"),
        products=_parse_products(item.get("enisaIdProduct", [])),
        vendors=_parse_vendors(item.get("enisaIdVendor", [])),
        raw=item,
    )


class EUVDClient:
    """Async client for the EUVD API."""

    def __init__(self, base_url: str = BASE_URL, timeout: float = 30.0, page_delay: float = 1.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.page_delay = page_delay

    async def _get(self, path: str, params: dict | None = None) -> dict:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(f"{self.base_url}{path}", params=params, headers={"accept": "application/json"})
            resp.raise_for_status()
            return resp.json()

    async def search(
        self,
        text: str = "",
        vendor: str = "",
        product: str = "",
        assigner: str = "",
        from_date: str = "",  # YYYY-MM-DD
        to_date: str = "",
        from_score: float = 0,
        to_score: float = 10,
        from_epss: float = 0,
        to_epss: float = 100,
        exploited: bool = False,
        page: int = 0,
        size: int = 100,
    ) -> EUVDSearchResult:
        params = {
            "text": text,
            "vendor": vendor,
            "product": product,
            "assigner": assigner,
            "fromDate": from_date,
            "toDate": to_date,
            "fromScore": from_score,
            "toScore": to_score,
            "fromEpss": from_epss,
            "toEpss": to_epss,
            "exploited": str(exploited).lower(),
            "page": page,
            "size": min(size, 100),
        }
        data = await self._get("/search", params)
        items = [_parse_record(i) for i in data.get("items", [])]
        return EUVDSearchResult(items=items, total=data.get("total", 0), page=page, size=size)

    async def last_vulnerabilities(self) -> list[EUVDRecord]:
        data = await self._get("/lastvulnerabilities")
        items = data if isinstance(data, list) else data.get("items", [])
        return [_parse_record(i) for i in items]

    async def exploited_vulnerabilities(self) -> list[EUVDRecord]:
        data = await self._get("/exploitedvulnerabilities")
        items = data if isinstance(data, list) else data.get("items", [])
        return [_parse_record(i) for i in items]

    async def critical_vulnerabilities(self) -> list[EUVDRecord]:
        data = await self._get("/criticalvulnerabilities")
        items = data if isinstance(data, list) else data.get("items", [])
        return [_parse_record(i) for i in items]

    async def by_id(self, euvd_id: str) -> EUVDRecord | None:
        data = await self._get("/enisaid", {"id": euvd_id})
        items = data if isinstance(data, list) else data.get("items", [])
        return _parse_record(items[0]) if items else None

    async def advisory(self, adv_id: str) -> dict | None:
        try:
            return await self._get("/advisory", {"id": adv_id})
        except httpx.HTTPStatusError:
            return None

    async def bulk_fetch_all(self, size: int = 100, max_pages: int | None = None) -> list[EUVDRecord]:
        """Paginate through ALL EUVD records. Respects rate limits with page_delay."""
        all_records: list[EUVDRecord] = []
        page = 0
        while True:
            if max_pages is not None and page >= max_pages:
                break
            logger.info("euvd_bulk_fetch", page=page, fetched=len(all_records))
            result = await self.search(page=page, size=size)
            all_records.extend(result.items)
            if (page + 1) * size >= result.total:
                break
            page += 1
            await asyncio.sleep(self.page_delay)
        logger.info("euvd_bulk_complete", total=len(all_records))
        return all_records

    async def incremental_fetch(self, since_date: str, size: int = 100) -> list[EUVDRecord]:
        """Fetch records published/updated since a given date."""
        all_records: list[EUVDRecord] = []
        page = 0
        while True:
            result = await self.search(from_date=since_date, page=page, size=size)
            all_records.extend(result.items)
            if (page + 1) * size >= result.total:
                break
            page += 1
            await asyncio.sleep(self.page_delay)
        return all_records
