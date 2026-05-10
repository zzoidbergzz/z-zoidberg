"""Normalize EUVD records into CorpusDocument upsert format.

Preserves ALL metadata in raw_json for rich pivots: CVSS vectors,
EPSS scores, product/version combos, vendor mappings, references, aliases.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.integrations.euvd.client import EUVDRecord


def _parse_euvd_date(date_str: str) -> datetime | None:
    """Parse EUVD date format: 'Apr 15, 2025, 8:30:58 PM'"""
    if not date_str:
        return None
    for fmt in ("%b %d, %Y, %I:%M:%S %p", "%b %d, %Y"):
        try:
            return datetime.strptime(date_str.strip(), fmt)
        except ValueError:
            continue
    return None


def normalize_euvd_record(record: EUVDRecord) -> dict[str, Any]:
    """Convert an EUVDRecord into a corpus_documents upsert dict."""
    # Build rich body text for full-text search
    parts = [record.description] if record.description else []

    if record.base_score is not None:
        cvss_line = f"CVSS {record.base_score_version or '3.1'} Score: {record.base_score}"
        if record.base_score_vector:
            cvss_line += f" | Vector: {record.base_score_vector}"
        parts.append(cvss_line)

    if record.epss is not None:
        parts.append(f"EPSS: {record.epss:.4f} ({record.epss * 100:.2f}%)")

    if record.vendors:
        vendor_names = ", ".join(v.name for v in record.vendors if v.name)
        if vendor_names:
            parts.append(f"Vendors: {vendor_names}")

    if record.products:
        prod_lines = []
        for p in record.products:
            line = p.name
            if p.product_version:
                line += f" (version: {p.product_version})"
            if line:
                prod_lines.append(line)
        if prod_lines:
            parts.append("Products: " + "; ".join(prod_lines))

    if record.aliases:
        parts.append("Aliases: " + ", ".join(record.aliases))

    if record.references:
        parts.append("References:\n" + "\n".join(record.references))

    if record.assigner:
        parts.append(f"Assigner: {record.assigner}")

    body_text = "\n\n".join(parts)

    # Title: first line of description, or the ID
    title = record.description.split("\n")[0][:200] if record.description else record.id

    # Search vector content: concatenate everything searchable
    search_parts = [record.id, record.description or ""]
    search_parts.extend(a for a in record.aliases if a)
    search_parts.extend(v.name for v in record.vendors if v.name)
    search_parts.extend(p.name for p in record.products if p.name)
    if record.assigner:
        search_parts.append(record.assigner)
    search_text = " ".join(search_parts)

    return {
        "corpus": "euvd",
        "external_id": record.id,
        "title": title,
        "summary": record.description,
        "body_text": body_text,
        "raw_json": record.raw,  # FULL original record for pivot richness
        "published_at": _parse_euvd_date(record.date_published),
        "modified_at": _parse_euvd_date(record.date_updated),
        "search_text": search_text,  # Used to generate tsvector via SQL
    }
