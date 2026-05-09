#!/usr/bin/env python3
"""Backfill payment URLs/crypto addresses for tor_site_findings claims."""

from __future__ import annotations

import argparse
import asyncio
import sys
import uuid
from pathlib import Path

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.config import settings
from app.database import AsyncSessionLocal
from app.models.claims import Claim
from app.models.documents import DocumentSection, ParsedDocument
from app.models.entities import Entity
from app.workers.onion_analysis import extract_onion_findings


def _unique(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        value = str(raw or "").strip()
        if not value:
            continue
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
    return out


async def _ensure_entity(db, tenant_id: uuid.UUID, kind: str, canonical_name: str) -> tuple[uuid.UUID, bool]:
    ins = (
        pg_insert(Entity.__table__)
        .values(
            tenant_id=tenant_id,
            kind=kind,
            canonical_name=canonical_name,
            external_refs={},
        )
        .on_conflict_do_nothing(index_elements=["tenant_id", "kind", "canonical_name"])
        .returning(Entity.__table__.c.id)
    )
    inserted = (await db.execute(ins)).scalar_one_or_none()
    if inserted is not None:
        return inserted, True
    existing = (
        await db.execute(
            select(Entity.id).where(
                Entity.tenant_id == tenant_id,
                Entity.kind == kind,
                Entity.canonical_name == canonical_name,
            )
        )
    ).scalar_one()
    return existing, False


async def _ensure_observed_claim(
    db,
    *,
    tenant_id: uuid.UUID,
    entity_id: uuid.UUID,
    source_url: str,
    document_id: str | None,
) -> bool:
    existing = (
        await db.execute(
            select(Claim.id).where(
                Claim.tenant_id == tenant_id,
                Claim.entity_id == entity_id,
                Claim.claim_type == "observed_in_document",
                Claim.value["source_url"].astext == source_url,
            ).limit(1)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return False
    payload = {"source_url": source_url, "backfill": "onion_payment_extraction"}
    if document_id:
        payload["document_id"] = document_id
    db.add(
        Claim(
            tenant_id=tenant_id,
            entity_id=entity_id,
            claim_type="observed_in_document",
            value=payload,
            confidence=0.8,
            status="pending",
        )
    )
    return True


async def _latest_document_text(db, tenant_id: uuid.UUID, source_url: str) -> tuple[str, str | None]:
    doc = (
        await db.execute(
            select(ParsedDocument)
            .where(
                ParsedDocument.tenant_id == tenant_id,
                ParsedDocument.url == source_url,
            )
            .order_by(ParsedDocument.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if doc is None:
        return "", None
    sections = (
        await db.execute(
            select(DocumentSection.content)
            .where(DocumentSection.document_id == doc.id)
            .order_by(DocumentSection.section_index.asc())
            .limit(100)
        )
    ).scalars().all()
    return "\n\n".join(s for s in sections if s), str(doc.id)


async def _fetch_live_onion_html(source_url: str) -> str:
    proxy = f"socks5h://{settings.TOR_SOCKS_HOST}:{settings.TOR_SOCKS_PORT}"
    headers: dict[str, str] = {}
    if settings.FEED_POLL_USER_AGENT:
        headers["User-Agent"] = settings.FEED_POLL_USER_AGENT
    async with httpx.AsyncClient(proxy=proxy, timeout=40, follow_redirects=True, headers=headers) as client:
        response = await client.get(source_url)
        response.raise_for_status()
        return response.text


async def run_backfill(
    source_url: str | None,
    tenant_id: str | None,
    dry_run: bool,
    limit: int | None,
    refetch_live: bool,
) -> None:
    stats = {"claims_checked": 0, "claims_updated": 0, "entities_added": 0, "links_added": 0}
    live_html_cache: dict[str, str] = {}
    async with AsyncSessionLocal() as db:
        query = select(Claim).where(Claim.claim_type == "tor_site_findings")
        if source_url:
            query = query.where(Claim.value["source_url"].astext == source_url)
        if tenant_id:
            query = query.where(Claim.tenant_id == uuid.UUID(tenant_id))
        query = query.order_by(Claim.created_at.desc())
        if limit:
            query = query.limit(limit)

        claims = (await db.execute(query)).scalars().all()
        for claim in claims:
            stats["claims_checked"] += 1
            value = claim.value if isinstance(claim.value, dict) else {}
            src = str(value.get("source_url", "")).strip()
            if not src:
                continue

            deterministic = value.get("deterministic", {}) or {}
            if not isinstance(deterministic, dict):
                deterministic = {}
            existing_addresses = _unique([str(v) for v in deterministic.get("payment_addresses", []) or []])
            existing_urls = _unique([str(v) for v in deterministic.get("payment_urls", []) or []])

            text_blob = str(value.get("raw_text_excerpt", "")).strip()
            doc_text, document_id = await _latest_document_text(db, claim.tenant_id, src)
            live_html = ""
            if refetch_live:
                if src not in live_html_cache:
                    try:
                        live_html_cache[src] = await _fetch_live_onion_html(src)
                    except Exception as exc:
                        print(f"WARN: live refetch failed for {src}: {exc}")
                        live_html_cache[src] = ""
                live_html = live_html_cache[src]

            joined_text = "\n\n".join(v for v in (live_html, text_blob, doc_text) if v.strip())
            if not joined_text:
                continue

            findings = extract_onion_findings(joined_text)
            merged_addresses = _unique(existing_addresses + findings.get("payment_addresses", []))
            merged_urls = _unique(existing_urls + findings.get("payment_urls", []))
            changed = merged_addresses != existing_addresses or merged_urls != existing_urls

            if changed:
                deterministic["payment_addresses"] = merged_addresses
                deterministic["payment_urls"] = merged_urls
                summary = deterministic.get("summary", {}) or {}
                if not isinstance(summary, dict):
                    summary = {}
                summary["payment_address_count"] = len(merged_addresses)
                summary["payment_url_count"] = len(merged_urls)
                deterministic["summary"] = summary
                value["deterministic"] = deterministic
                claim.value = value
                stats["claims_updated"] += 1

            for address in merged_addresses:
                if not address:
                    continue
                entity_id, created = await _ensure_entity(db, claim.tenant_id, "indicator", address)
                if created:
                    stats["entities_added"] += 1
                if await _ensure_observed_claim(
                    db,
                    tenant_id=claim.tenant_id,
                    entity_id=entity_id,
                    source_url=src,
                    document_id=document_id,
                ):
                    stats["links_added"] += 1

            for payment_url in merged_urls:
                if not payment_url:
                    continue
                entity_id, created = await _ensure_entity(db, claim.tenant_id, "url", payment_url)
                if created:
                    stats["entities_added"] += 1
                if await _ensure_observed_claim(
                    db,
                    tenant_id=claim.tenant_id,
                    entity_id=entity_id,
                    source_url=src,
                    document_id=document_id,
                ):
                    stats["links_added"] += 1

        if dry_run:
            await db.rollback()
        else:
            await db.commit()

    mode = "DRY RUN" if dry_run else "APPLIED"
    print(
        f"{mode}: checked={stats['claims_checked']} updated={stats['claims_updated']} "
        f"entities_linked={stats['entities_added']} claims_linked={stats['links_added']}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill tor-site payment addresses/URLs as searchable entities")
    parser.add_argument("--source-url", default=None, help="Restrict backfill to one onion source URL")
    parser.add_argument("--tenant-id", default=None, help="Restrict backfill to one tenant UUID")
    parser.add_argument("--dry-run", action="store_true", help="Compute and print without committing changes")
    parser.add_argument("--limit", type=int, default=None, help="Max tor_site_findings claims to process")
    parser.add_argument(
        "--refetch-live",
        action="store_true",
        help="Fetch onion HTML again via Tor before extracting payment links/addresses",
    )
    args = parser.parse_args()
    asyncio.run(run_backfill(args.source_url, args.tenant_id, args.dry_run, args.limit, args.refetch_live))


if __name__ == "__main__":
    main()
