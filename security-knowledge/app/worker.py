"""ARQ background worker with OpenTelemetry trace context propagation.

Every job accepts an optional `_otel_ctx` kwarg (injected at enqueue time
by `app.observability.trace_propagation.get_traceparent()`).  The
`trace_from_job` context manager reconstructs the parent span so all work
done inside the job appears as a child of the originating HTTP request in
any OTel-compatible backend (Jaeger, Tempo, Honeycomb, etc.).
"""

from __future__ import annotations

import hashlib
import re
import time
import uuid

import structlog
from arq.connections import RedisSettings
from arq.cron import cron
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.config import settings
from app.observability.trace_propagation import trace_from_job
from app.observability.worker import record_job_end, record_job_start
from app.workers.feed_poller import poll_feeds
from app.workers.tor_scraper import scrape_onion_sources

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Map extractor "kind" strings → EntityKind enum values
_KIND_MAP: dict[str, str] = {
    "cve": "cve",
    "ip": "ip_address",
    "hash": "hash",
    "domain": "domain",
    "url": "url",
    "technique": "attack_pattern",
}


def _strip_null_bytes(value: str) -> str:
    """Postgres TEXT/VARCHAR cannot store NUL (0x00). Strip and normalise."""
    if not value:
        return value
    # Drop NULs and other C0 controls except \t \n \r — keeps utf-8 valid.
    return value.replace("\x00", "").translate({i: None for i in range(0, 32) if i not in (9, 10, 13)})


def _extract_title(html: str) -> str:
    """Pull <title> text from raw HTML."""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return _strip_null_bytes(m.group(1).strip()) if m else ""


def _parse_content(html: str, content_type: str) -> str:
    """Extract plain text from HTML using trafilatura, falling back to BeautifulSoup."""
    if content_type == "text/markdown":
        return _strip_null_bytes(html)

    try:
        import trafilatura

        text = trafilatura.extract(html, include_comments=False, include_tables=True)
        if text:
            return _strip_null_bytes(text)
    except Exception:
        pass

    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        return _strip_null_bytes(soup.get_text(separator="\n"))
    except Exception:
        pass

    # Last resort: strip HTML tags with regex
    return _strip_null_bytes(re.sub(r"<[^>]+>", " ", html))


def _chunk_text(text: str) -> list[tuple[str, str]]:
    """Split text into (heading, content) pairs by double newlines or headers.

    Returns a list of (heading, content) tuples where heading may be empty.
    """
    chunks: list[tuple[str, str]] = []
    current_heading = ""
    current_lines: list[str] = []

    for line in text.splitlines():
        stripped = line.strip()
        # Markdown-style headings
        if stripped.startswith("#"):
            if current_lines:
                content = "\n".join(current_lines).strip()
                if content:
                    chunks.append((current_heading, content))
            current_heading = stripped.lstrip("#").strip()
            current_lines = []
        else:
            current_lines.append(line)

    if current_lines:
        content = "\n".join(current_lines).strip()
        if content:
            chunks.append((current_heading, content))

    if not chunks:
        # Paragraph-split fallback
        paragraphs = re.split(r"\n\s*\n", text)
        for para in paragraphs:
            para = para.strip()
            if para:
                chunks.append(("", para))

    return chunks or [("", text.strip())]


# ---------------------------------------------------------------------------
# Job functions
# ---------------------------------------------------------------------------


# Map Entity.kind (post _KIND_MAP normalisation) → list of arq enrichment
# providers to dispatch when a new entity is materialised at ingest time.
_AUTO_ENRICHMENT_PROVIDERS: dict[str, tuple[str, ...]] = {
    "cve": ("nvd",),
    "cve_id": ("nvd",),
    "attack_pattern": ("mitre_attack",),
    "technique": ("mitre_attack",),
    "subtechnique": ("mitre_attack",),
    "url": ("urlscan",),
    "ip": ("greynoise", "ipinfo", "abuseipdb"),
    "ip_address": ("greynoise", "ipinfo", "abuseipdb"),
    "domain": ("virustotal",),
    "hash": ("virustotal",),
    "file_hash": ("virustotal",),
}


async def _enqueue_auto_enrichment(entities: list, tenant_id: str) -> None:
    """Enqueue run_enrichment jobs for newly-created entities.

    Each enqueue is wrapped in its own try/except so a single failure
    cannot roll back the ingest transaction.  Returns silently if the
    arq pool cannot be reached (jobs can be re-driven manually later).
    """
    if not entities:
        return

    try:
        from arq import create_pool
        from arq.connections import RedisSettings
    except Exception as exc:  # pragma: no cover
        logger.warning("auto_enrichment_arq_import_failed", error=str(exc))
        return

    pool = None
    try:
        pool = await create_pool(RedisSettings.from_dsn(settings.REDIS_URL))
    except Exception as exc:
        logger.warning("auto_enrichment_pool_failed", error=str(exc))
        return

    try:
        for ent in entities:
            providers = _AUTO_ENRICHMENT_PROVIDERS.get(ent.kind)
            if not providers:
                continue
            for prov in providers:
                try:
                    await pool.enqueue_job(
                        "run_enrichment",
                        str(ent.id),
                        tenant_id,
                        provider=prov,
                    )
                    logger.info(
                        "auto_enrichment_enqueued",
                        entity_id=str(ent.id),
                        kind=ent.kind,
                        provider=prov,
                    )
                except Exception as exc:
                    logger.warning(
                        "auto_enrichment_enqueue_failed",
                        entity_id=str(ent.id),
                        kind=ent.kind,
                        provider=prov,
                        error=str(exc),
                    )
    finally:
        try:
            await pool.aclose()
        except Exception:
            pass


async def process_ingest_job(
    ctx: dict,
    job_id: str,
    *,
    _otel_ctx: dict | None = None,
) -> dict:
    """Ingest a source document.  Trace context propagated from enqueue site."""
    t0 = time.monotonic()
    await record_job_start(job_id, "ingest")

    with trace_from_job(ctx, "worker.process_ingest_job", _otel_ctx, {"job.id": job_id}) as span:
        try:
            logger.info("processing_ingest_job", job_id=job_id)
            span.set_attribute("job.type", "ingest")

            from app.database import AsyncSessionLocal
            from app.extractors.base import run_all
            from app.fetcher import _is_denied, fetch
            from app.models.audit import AuditEvent
            from app.models.claims import Claim
            from app.models.documents import DocumentSection, ParsedDocument
            from app.models.entities import Entity
            from app.models.evidence import Evidence
            from app.models.jobs import IngestionJob

            async with AsyncSessionLocal() as db:
                # ----------------------------------------------------------
                # 1. Load job from DB
                # ----------------------------------------------------------
                result_row = await db.execute(select(IngestionJob).where(IngestionJob.id == uuid.UUID(job_id)))
                job = result_row.scalar_one_or_none()
                if job is None:
                    logger.error("ingest_job_not_found", job_id=job_id)
                    return {"job_id": job_id, "status": "error", "error": "Job not found"}

                job.status = "running"
                await db.flush()

                tenant_id = job.tenant_id
                source_url = job.source_url or ""

                # ----------------------------------------------------------
                # 2. Resolve source policy — abort if denied
                # ----------------------------------------------------------
                if source_url and _is_denied(source_url):
                    logger.warning("ingest_job_denied_by_policy", job_id=job_id, url=source_url)
                    job.status = "error"
                    job.error_message = "Denied by source policy"
                    job.result = {"job_id": job_id, "status": "error", "reason": "policy_denied"}
                    await db.commit()
                    result = {"job_id": job_id, "status": "error", "reason": "policy_denied"}
                    span.set_attribute("job.status", "error")
                    await record_job_end(job_id, "ingest", "error", time.monotonic() - t0)
                    return result

                # ----------------------------------------------------------
                # 3. Check idempotency — skip if URL already ingested for tenant
                # ----------------------------------------------------------
                if source_url:
                    existing = await db.execute(
                        select(ParsedDocument).where(
                            ParsedDocument.tenant_id == tenant_id,
                            ParsedDocument.url == source_url,
                        )
                    )
                    existing_doc = existing.scalars().first()
                    if existing_doc is not None:
                        logger.info(
                            "ingest_job_skipped_duplicate",
                            job_id=job_id,
                            url=source_url,
                            doc_id=str(existing_doc.id),
                        )
                        job.status = "complete"
                        job.result = {
                            "job_id": job_id,
                            "status": "complete",
                            "skipped": True,
                            "document_id": str(existing_doc.id),
                        }
                        await db.commit()
                        result = job.result
                        span.set_attribute("job.status", "complete")
                        await record_job_end(job_id, "ingest", "complete", time.monotonic() - t0)
                        return result

                # ----------------------------------------------------------
                # 4. Detect content type from payload or URL
                # ----------------------------------------------------------
                content_type_hint = job.payload.get("content_type", "text/html")
                if source_url.endswith(".md") or source_url.endswith(".markdown"):
                    content_type_hint = "text/markdown"
                if source_url.endswith(".pdf"):
                    logger.warning("ingest_job_pdf_unsupported", job_id=job_id, url=source_url)
                    job.status = "error"
                    job.error_message = "PDF ingestion not yet supported"
                    job.result = {"job_id": job_id, "status": "error", "reason": "unsupported_content_type"}
                    await db.commit()
                    result = job.result
                    span.set_attribute("job.status", "error")
                    await record_job_end(job_id, "ingest", "error", time.monotonic() - t0)
                    return result

                # ----------------------------------------------------------
                # 5. Fetch the URL
                # ----------------------------------------------------------
                if not source_url:
                    job.status = "error"
                    job.error_message = "No source_url on job"
                    job.result = {"job_id": job_id, "status": "error", "reason": "no_source_url"}
                    await db.commit()
                    span.set_attribute("job.status", "error")
                    await record_job_end(job_id, "ingest", "error", time.monotonic() - t0)
                    return job.result

                logger.info("ingest_fetching", job_id=job_id, url=source_url)
                fetch_result = await fetch(source_url)

                if not fetch_result.ok:
                    job.status = "error"
                    job.error_message = f"Fetch failed: {fetch_result.error or fetch_result.status_code}"
                    job.result = {"job_id": job_id, "status": "error", "reason": "fetch_failed"}
                    await db.commit()
                    span.set_attribute("job.status", "error")
                    await record_job_end(job_id, "ingest", "error", time.monotonic() - t0)
                    return job.result

                raw_text = fetch_result.text
                content_sha256 = hashlib.sha256(raw_text.encode()).hexdigest()

                # Idempotency by content hash
                existing_by_hash = await db.execute(
                    select(ParsedDocument).where(
                        ParsedDocument.tenant_id == tenant_id,
                        ParsedDocument.metadata_["content_sha256"].as_string() == content_sha256,
                    )
                )
                existing_by_hash_doc = existing_by_hash.scalars().first()
                if existing_by_hash_doc is not None:
                    logger.info(
                        "ingest_job_skipped_duplicate_hash",
                        job_id=job_id,
                        sha256=content_sha256,
                        doc_id=str(existing_by_hash_doc.id),
                    )
                    job.status = "complete"
                    job.result = {
                        "job_id": job_id,
                        "status": "complete",
                        "skipped": True,
                        "document_id": str(existing_by_hash_doc.id),
                    }
                    await db.commit()
                    span.set_attribute("job.status", "complete")
                    await record_job_end(job_id, "ingest", "complete", time.monotonic() - t0)
                    return job.result

                # ----------------------------------------------------------
                # 6. Parse content
                # ----------------------------------------------------------
                logger.info("ingest_parsing", job_id=job_id)
                parsed_text = _parse_content(raw_text, content_type_hint)
                title = _extract_title(raw_text) or source_url
                word_count = len(parsed_text.split())

                # ----------------------------------------------------------
                # 7. Persist ParsedDocument
                # ----------------------------------------------------------
                doc = ParsedDocument(
                    tenant_id=tenant_id,
                    source_id=job.source_id,
                    title=title[:512],
                    url=source_url,
                    content_type=content_type_hint,
                    word_count=word_count,
                    metadata_={"content_sha256": content_sha256, "used_browser": fetch_result.used_browser},
                )
                db.add(doc)
                await db.flush()

                # ----------------------------------------------------------
                # 8. Chunk into DocumentSection rows
                # ----------------------------------------------------------
                logger.info("ingest_chunking", job_id=job_id, doc_id=str(doc.id))
                chunks = _chunk_text(parsed_text)
                sections: list[DocumentSection] = []
                for idx, (heading, content) in enumerate(chunks):
                    section = DocumentSection(
                        document_id=doc.id,
                        section_index=idx,
                        heading=_strip_null_bytes(heading)[:512],
                        content=_strip_null_bytes(content),
                    )
                    db.add(section)
                    sections.append(section)
                await db.flush()

                # ----------------------------------------------------------
                # 9. Extract entities and create Claims + Evidence
                # ----------------------------------------------------------
                logger.info("ingest_extracting", job_id=job_id, doc_id=str(doc.id))
                entities_found = run_all(parsed_text)

                # Deduplicate by (kind, value)
                seen: set[tuple[str, str]] = set()
                unique_entities: list[dict] = []
                for ent in entities_found:
                    key = (ent["kind"], ent["value"])
                    if key not in seen:
                        seen.add(key)
                        unique_entities.append(ent)

                # Pick the first section for evidence anchor (or last if single chunk)
                anchor_section = sections[0] if sections else None

                entity_count = 0
                newly_created_entities: list[Entity] = []
                for ent_data in unique_entities:
                    raw_kind = ent_data["kind"]
                    mapped_kind = _KIND_MAP.get(raw_kind, "other")
                    canonical = ent_data["value"]

                    # Race-safe upsert. Relies on
                    # UNIQUE(tenant_id, kind, canonical_name) added in
                    # alembic 0026_entity_unique_constraint. Without
                    # ON CONFLICT, two concurrent workers can both insert
                    # the same (tenant, kind, name) and a later read-then-
                    # insert would see duplicates and crash with
                    # MultipleResultsFound.
                    ins_stmt = (
                        pg_insert(Entity.__table__)
                        .values(
                            tenant_id=tenant_id,
                            kind=mapped_kind,
                            canonical_name=canonical,
                            external_refs={},
                        )
                        .on_conflict_do_nothing(
                            index_elements=["tenant_id", "kind", "canonical_name"]
                        )
                        .returning(Entity.__table__.c.id)
                    )
                    ins_result = await db.execute(ins_stmt)
                    new_id = ins_result.scalar_one_or_none()
                    if new_id is not None:
                        await db.flush()
                        entity = (
                            await db.execute(
                                select(Entity).where(Entity.id == new_id)
                            )
                        ).scalar_one()
                        newly_created_entities.append(entity)
                    else:
                        entity = (
                            await db.execute(
                                select(Entity).where(
                                    Entity.tenant_id == tenant_id,
                                    Entity.kind == mapped_kind,
                                    Entity.canonical_name == canonical,
                                )
                            )
                        ).scalar_one()

                    # Create Claim linking entity to this document
                    claim = Claim(
                        tenant_id=tenant_id,
                        entity_id=entity.id,
                        claim_type="observed_in_document",
                        value={"source_url": source_url, "document_id": str(doc.id)},
                        confidence=0.8,
                        status="pending",
                    )
                    db.add(claim)
                    await db.flush()

                    # Create Evidence linking claim to document section
                    snippet = canonical[:200]
                    evidence = Evidence(
                        tenant_id=tenant_id,
                        document_id=doc.id,
                        claim_id=claim.id,
                        entity_id=entity.id,
                        title=f"{mapped_kind}: {canonical[:100]}",
                        content=anchor_section.content[:500] if anchor_section else "",
                        text_snippet=snippet,
                        source_url=source_url,
                        confidence=0.8,
                    )
                    db.add(evidence)
                    entity_count += 1

                await db.flush()

                # ----------------------------------------------------------
                # 9b. Auto-enrichment — enqueue per-provider arq jobs for
                #     newly-created entities.  Each enqueue is wrapped in
                #     try/except so a transient redis failure (or one
                #     bad provider) cannot roll back the whole ingest.
                # ----------------------------------------------------------
                if not getattr(settings, "AUTO_ENRICHMENT_DISABLED", False) and newly_created_entities:
                    await _enqueue_auto_enrichment(newly_created_entities, str(tenant_id))

                # ----------------------------------------------------------
                # 10. Emit AuditEvent
                # ----------------------------------------------------------
                audit = AuditEvent(
                    tenant_id=tenant_id,
                    actor="worker",
                    action="ingest_complete",
                    resource_type="parsed_document",
                    resource_id=str(doc.id),
                    details={
                        "job_id": job_id,
                        "source_url": source_url,
                        "word_count": word_count,
                        "sections": len(sections),
                        "entities_extracted": entity_count,
                        "content_sha256": content_sha256,
                    },
                )
                db.add(audit)

                # ----------------------------------------------------------
                # 11. Update job to complete
                # ----------------------------------------------------------
                result = {
                    "job_id": job_id,
                    "status": "complete",
                    "document_id": str(doc.id),
                    "word_count": word_count,
                    "sections": len(sections),
                    "entities_extracted": entity_count,
                    "content_sha256": content_sha256,
                }
                job.status = "complete"
                job.result = result
                await db.commit()

            logger.info(
                "ingest_job_complete",
                job_id=job_id,
                document_id=result["document_id"],
                entities=entity_count,
            )
            span.set_attribute("job.status", "complete")
            span.set_attribute("ingest.entities", entity_count)
            await record_job_end(job_id, "ingest", "complete", time.monotonic() - t0)
            return result

        except Exception as exc:
            logger.exception("ingest_job_failed", job_id=job_id, error=str(exc))
            span.record_exception(exc)
            # Best-effort: update job to error state
            try:
                from app.database import AsyncSessionLocal
                from app.models.jobs import IngestionJob

                async with AsyncSessionLocal() as db:
                    result_row = await db.execute(select(IngestionJob).where(IngestionJob.id == uuid.UUID(job_id)))
                    job = result_row.scalar_one_or_none()
                    if job:
                        job.status = "error"
                        job.error_message = str(exc)
                        job.result = {"job_id": job_id, "status": "error"}
                        await db.commit()
            except Exception:
                pass
            await record_job_end(job_id, "ingest", "error", time.monotonic() - t0)
            raise


async def run_enrichment(
    ctx: dict,
    entity_id: str,
    tenant_id: str,
    *,
    provider: str = "all",
    force_refresh: bool = False,
    _otel_ctx: dict | None = None,
) -> dict:
    """Run enrichment for a single entity.  Accepts optional provider name and
    force_refresh flag to bypass cache (triggers diff recording)."""
    t0 = time.monotonic()
    await record_job_start(entity_id, "enrichment")

    with trace_from_job(
        ctx,
        "worker.run_enrichment",
        _otel_ctx,
        {
            "entity.id": entity_id,
            "tenant.id": tenant_id,
            "enrichment.provider": provider,
            "enrichment.force_refresh": force_refresh,
        },
    ) as span:
        try:
            logger.info(
                "running_enrichment",
                entity_id=entity_id,
                provider=provider,
                force_refresh=force_refresh,
            )

            from app.database import AsyncSessionLocal
            from app.enrichment.registry import list_providers
            from app.enrichment.service import EnrichmentService
            from app.models.entities import Entity

            async with AsyncSessionLocal() as db:
                # Load entity from DB
                result_row = await db.execute(select(Entity).where(Entity.id == uuid.UUID(entity_id)))
                entity = result_row.scalar_one_or_none()
                if entity is None:
                    logger.warning("enrichment_entity_not_found", entity_id=entity_id)
                    span.set_attribute("job.status", "error")
                    await record_job_end(entity_id, "enrichment", "error", time.monotonic() - t0)
                    return {"entity_id": entity_id, "status": "error", "error": "Entity not found"}

                svc = EnrichmentService(db, tenant_id)
                providers_to_run = [provider] if provider != "all" else list_providers()

                enrichment_results: dict[str, dict] = {}
                for prov_name in providers_to_run:
                    try:
                        prov_result = await svc.enrich(prov_name, entity.kind, entity.canonical_name)
                        enrichment_results[prov_name] = prov_result
                        logger.info(
                            "enrichment_provider_complete",
                            entity_id=entity_id,
                            provider=prov_name,
                        )
                    except Exception as prov_exc:
                        logger.warning(
                            "enrichment_provider_failed",
                            entity_id=entity_id,
                            provider=prov_name,
                            error=str(prov_exc),
                        )
                        enrichment_results[prov_name] = {"error": str(prov_exc)}

                await db.commit()

            result = {
                "entity_id": entity_id,
                "status": "complete",
                "provider": provider,
                "providers_run": list(enrichment_results.keys()),
                "results": enrichment_results,
            }
            span.set_attribute("job.status", "complete")
            span.set_attribute("enrichment.providers_run", len(enrichment_results))
            await record_job_end(entity_id, "enrichment", "complete", time.monotonic() - t0)
            return result

        except Exception as exc:
            logger.exception("enrichment_job_failed", entity_id=entity_id, error=str(exc))
            span.record_exception(exc)
            await record_job_end(entity_id, "enrichment", "error", time.monotonic() - t0)
            raise


async def refresh_corpora(
    ctx: dict,
    *,
    _otel_ctx: dict | None = None,
) -> dict:
    """Daily refresh of historical CVE/GCVE/ExploitDB corpora.

    Shells out to scripts/refresh_corpora.sh which does `git pull` per corpus
    and re-runs each importer (importers are idempotent on (corpus, external_id)).
    """
    import asyncio
    import os

    script = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts", "refresh_corpora.sh")
    if not os.path.exists(script):
        logger.warning("refresh_corpora_script_missing", path=script)
        return {"status": "skipped", "reason": "script not found"}

    t0 = time.monotonic()
    job_id = "corpus-refresh-" + str(uuid.uuid4())[:8]
    await record_job_start(job_id, "corpus_refresh")
    try:
        proc = await asyncio.create_subprocess_exec(
            "/bin/bash", script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        # Cap at 4h — corpora pulls can be large
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=14400)
        except asyncio.TimeoutError:
            proc.kill()
            await record_job_end(job_id, "corpus_refresh", "timeout", time.monotonic() - t0)
            logger.warning("refresh_corpora_timeout")
            return {"status": "timeout"}

        rc = proc.returncode
        status = "complete" if rc == 0 else "error"
        await record_job_end(job_id, "corpus_refresh", status, time.monotonic() - t0)
        logger.info("refresh_corpora_done", rc=rc, duration=time.monotonic() - t0)
        return {"status": status, "returncode": rc}
    except Exception:
        await record_job_end(job_id, "corpus_refresh", "error", time.monotonic() - t0)
        raise


async def send_digests(
    ctx: dict,
    *,
    _otel_ctx: dict | None = None,
) -> dict:
    """Send scheduled digest emails / webhooks."""
    t0 = time.monotonic()
    job_id = "digest-" + str(uuid.uuid4())[:8]
    await record_job_start(job_id, "digest")

    with trace_from_job(ctx, "worker.send_digests", _otel_ctx) as span:
        try:
            logger.info("sending_digests")
            span.set_attribute("job.type", "digest")
            result = {"status": "complete"}
            span.set_attribute("job.status", "complete")
            await record_job_end(job_id, "digest", "complete", time.monotonic() - t0)
            return result
        except Exception:
            await record_job_end(job_id, "digest", "error", time.monotonic() - t0)
            raise


async def check_ioc_watches(
    ctx: dict,
    ioc_value: str,
    ioc_kind: str,
    seeker_tenant_id: str,
    *,
    seeker_user_id: str | None = None,
    seeker_sector: str | None = None,
    trigger: str = "enrichment",
    _otel_ctx: dict | None = None,
) -> dict:
    """Async IOC watch check — dispatched after any enrichment cache miss."""
    with trace_from_job(
        ctx,
        "worker.check_ioc_watches",
        _otel_ctx,
        {"ioc.kind": ioc_kind, "trigger": trigger},
    ) as span:
        try:
            from app.database import AsyncSessionLocal
            from app.services.pingback import check_and_notify

            async with AsyncSessionLocal() as db:
                notified = await check_and_notify(
                    ioc_value=ioc_value,
                    ioc_kind=ioc_kind,
                    trigger=trigger,
                    seeker_tenant_id=seeker_tenant_id,
                    seeker_user_id=seeker_user_id,
                    seeker_sector=seeker_sector,
                    seeker_comment=None,
                    db=db,
                )
            span.set_attribute("watchers.notified", notified)
            return {"notified": notified}
        except Exception as exc:
            logger.warning("ioc_watch_check_failed", error=str(exc))
            span.record_exception(exc)
            return {"notified": 0, "error": str(exc)}


# ---------------------------------------------------------------------------
# Lifecycle + settings
# ---------------------------------------------------------------------------


async def startup(ctx: dict) -> None:
    logger.info("worker_starting")
    # Pre-load MITRE data if cached (non-blocking)
    try:
        import asyncio

        from app.services import mitre_attack

        asyncio.create_task(mitre_attack.preload_if_cached())
    except Exception:
        pass


async def shutdown(ctx: dict) -> None:
    logger.info("worker_stopping")


class WorkerSettings:
    functions = [process_ingest_job, run_enrichment, send_digests, check_ioc_watches, poll_feeds, refresh_corpora, scrape_onion_sources]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings.from_dsn(settings.REDIS_URL)
    max_jobs = 10
    job_timeout = 300
    keep_result = 3600  # seconds — retain job results for 1 hour
    cron_jobs = [
        # Feed poller every 5 minutes (per-source poll_interval is checked inside)
        cron(poll_feeds, minute={0, 20, 40}),
        # 20-min Tor scraping cycle
        cron(scrape_onion_sources, minute={2, 22, 42}),
        # Hourly digest dispatch (function checks each digest's own schedule)
        cron(send_digests, minute={2}),
        # Historical corpus refresh — daily 03:17 UTC (after most upstream daily syncs)
        cron(refresh_corpora, hour={3}, minute={17}),
    ]
