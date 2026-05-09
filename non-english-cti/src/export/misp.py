"""MISP event creation workflow."""

from __future__ import annotations
import logging
from typing import Optional

from ..models.record import CTIRecord

logger = logging.getLogger(__name__)


def create_misp_event(record: CTIRecord, org_uuid: str = "") -> dict:
    """Create a MISP event from a CTI record.

    Returns a dict compatible with PyMISP event creation.
    """
    event = {
        "info": record.title_en or record.title_original,
        "analysis": 0,  # Initial
        "threat_level_id": _map_threat_level(record),
        "distribution": 0,  # Organisation only
        "date": (record.published_at or record.collected_at).strftime("%Y-%m-%d"),
        "Attribute": [],
        "Tag": [],
        "Galaxy": [],
    }

    if org_uuid:
        event["orgc_uuid"] = org_uuid

    # Add attributes for IOCs
    if record.extracted_iocs:
        for ip in (record.extracted_iocs.ipv4 or []):
            event["Attribute"].append({
                "type": "ip-dst",
                "value": ip,
                "category": "Network activity",
                "to_ids": True,
                "comment": f"From {record.source_type}: {record.title_original}",
            })

        for domain in (record.extracted_iocs.domains or []):
            event["Attribute"].append({
                "type": "domain",
                "value": domain,
                "category": "Network activity",
                "to_ids": True,
                "comment": f"From {record.source_type}: {record.title_original}",
            })

        for sha256 in (record.extracted_iocs.sha256_hashes or []):
            event["Attribute"].append({
                "type": "sha256",
                "value": sha256,
                "category": "Payload delivery",
                "to_ids": True,
                "comment": f"From {record.source_type}: {record.title_original}",
            })

        for url in (record.extracted_iocs.urls or []):
            event["Attribute"].append({
                "type": "url",
                "value": url,
                "category": "Network activity",
                "to_ids": True,
                "comment": f"From {record.source_type}: {record.title_original}",
            })

        for email in (record.extracted_iocs.email_addresses or []):
            event["Attribute"].append({
                "type": "email-dst",
                "value": email,
                "category": "Network activity",
                "to_ids": True,
            })

    # Add CVE attributes
    for cve_id in record.extracted_cves:
        event["Attribute"].append({
            "type": "vulnerability",
            "value": cve_id,
            "category": "External analysis",
            "to_ids": False,
        })

    # Add tags
    tags = [
        f"source:{record.source_type}",
        f"country:{record.country}",
        f"region:{record.region}",
        f"language:{record.language_detected}",
        "tlp:amber",  # Default TLP for CTI
    ]
    if record.analyst_status == "approved":
        tags.append("verified:true")

    for actor in record.extractedactors:
        tags.append(f"threat-actor:{actor}")

    for malware in record.extracted_malware:
        tags.append(f"malware:{malware}")

    event["Tag"] = [{"name": tag} for tag in tags]

    # Add external reference
    event.setdefault("external_references", [])
    event["external_references"].append({
        "source": record.source_type,
        "url": record.source_url,
        "comment": f"Original ({record.language_detected}): {record.title_original}",
    })

    return event


def _map_threat_level(record: CTIRecord) -> int:
    """Map record confidence to MISP threat level (1-4, lower = more severe)."""
    if record.confidence_score >= 0.8:
        return 2  # Medium
    elif record.confidence_score >= 0.5:
        return 3  # Low
    else:
        return 4  # Undefined
