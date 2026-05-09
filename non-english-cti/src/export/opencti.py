"""OpenCTI ingestion workflow."""

from __future__ import annotations
import logging
from typing import Optional

from ..models.record import CTIRecord

logger = logging.getLogger(__name__)


def create_opencti_report(record: CTIRecord) -> dict:
    """Create an OpenCTI report payload from a CTI record.

    Returns dict compatible with OpenCTI GraphQL API.
    """
    report = {
        "name": record.title_en or record.title_original,
        "description": record.body_en or record.body_original,
        "published": (record.published_at or record.collected_at).isoformat(),
        "report_types": [record.source_type],
        "confidence": int(record.confidence_score * 100),
        "object_refs": [],
        "external_references": [
            {
                "source_name": record.source_type,
                "url": record.source_url,
                "description": f"Original in {record.language_detected}: {record.title_original}",
            }
        ],
        "labels": [
            record.source_type,
            record.country,
            record.region,
            f"language:{record.language_detected}",
            "non-english-cti",
        ],
        "x_opencti_original_title": record.title_original,
        "x_opencti_original_body": record.body_original,
        "x_opencti_translation_method": record.translation_method,
        "x_opencti_translation_confidence": record.translation_confidence,
        "x_opencti_language_detected": record.language_detected,
    }

    # Add IOC observables
    if record.extracted_iocs:
        for ip in (record.extracted_iocs.ipv4 or []):
            report["object_refs"].append({
                "type": "IPv4-Addr",
                "value": ip,
            })
        for domain in (record.extracted_iocs.domains or []):
            report["object_refs"].append({
                "type": "Domain-Name",
                "value": domain,
            })
        for sha256 in (record.extracted_iocs.sha256_hashes or []):
            report["object_refs"].append({
                "type": "File",
                "hashes": {"SHA-256": sha256},
            })

    # Add CVEs as vulnerabilities
    for cve_id in record.extracted_cves:
        report["object_refs"].append({
            "type": "Vulnerability",
            "name": cve_id,
            "external_id": cve_id,
        })

    # Add threat actors
    for actor in record.extracted_actors:
        report["object_refs"].append({
            "type": "Threat-Actor",
            "name": actor,
        })

    # Add malware
    for malware_name in record.extracted_malware:
        report["object_refs"].append({
            "type": "Malware",
            "name": malware_name,
            "is_family": True,
        })

    return report
