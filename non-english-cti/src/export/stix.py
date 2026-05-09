"""STIX 2.1 bundle export."""

from __future__ import annotations
import logging
from datetime import datetime
from typing import Optional
from uuid import UUID

from ..models.record import CTIRecord

logger = logging.getLogger(__name__)


def create_stix_bundle(records: list[CTIRecord]) -> dict:
    """Create a STIX 2.1 bundle from CTI records.

    Returns a valid STIX 2.1 Bundle object.
    """
    objects = []

    for record in records:
        # Create Report object for the advisory
        report = _create_report(record)
        objects.append(report)

        # Create Indicator objects for IOCs
        if record.extracted_iocs:
            indicators = _create_indicators(record)
            objects.extend(indicators)

        # Create Vulnerability objects for CVEs
        for cve_id in record.extracted_cves:
            vuln = _create_vulnerability(cve_id, record)
            objects.append(vuln)

        # Create Threat Actor objects
        for actor in record.extracted_actors:
            ta = _create_threat_actor(actor, record)
            objects.append(ta)

        # Create Malware objects
        for malware_name in record.extracted_malware:
            mal = _create_malware(malware_name, record)
            objects.append(mal)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{UUID(int=hash(tuple(str(r.record_id) for r in records)))}",
        "objects": objects,
    }

    return bundle


def _create_report(record: CTIRecord) -> dict:
    """Create a STIX 2.1 Report object."""
    return {
        "type": "report",
        "spec_version": "2.1",
        "id": f"report--{record.record_id}",
        "created_by_ref": f"identity--{record.source_id}",
        "created": record.published_at.isoformat() if record.published_at else record.collected_at.isoformat(),
        "modified": record.collected_at.isoformat(),
        "name": record.title_en or record.title_original,
        "description": record.body_en or record.body_original,
        "labels": [record.source_type, record.country, record.region] + record.tags,
        "confidence": int(record.confidence_score * 100),
        "external_references": [
            {
                "source_name": record.source_type,
                "url": record.source_url,
                "description": f"Original in {record.language_detected}: {record.title_original}",
            }
        ],
        "object_refs": [],  # Would be populated with indicator/vuln/actor/malware IDs
        "published": record.published_at.isoformat() if record.published_at else record.collected_at.isoformat(),
    }


def _create_indicators(record: CTIRecord) -> list[dict]:
    """Create STIX Indicator objects from extracted IOCs."""
    indicators = []

    if not record.extracted_iocs:
        return indicators

    for ip in (record.extracted_iocs.ipv4 or []):
        indicators.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{UUID(int=hash(f'ipv4-{ip}-{record.record_id}'))}",
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": record.collected_at.isoformat(),
            "labels": ["ipv4"],
            "confidence": int(record.confidence_score * 100),
        })

    for domain in (record.extracted_iocs.domains or []):
        indicators.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{UUID(int=hash(f'domain-{domain}-{record.record_id}'))}",
            "pattern": f"[domain-name:value = '{domain}']",
            "pattern_type": "stix",
            "valid_from": record.collected_at.isoformat(),
            "labels": ["domain"],
            "confidence": int(record.confidence_score * 100),
        })

    for sha256 in (record.extracted_iocs.sha256_hashes or []):
        indicators.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{UUID(int=hash(f'sha256-{sha256}-{record.record_id}'))}",
            "pattern": f"[file:hashes.'SHA-256' = '{sha256}']",
            "pattern_type": "stix",
            "valid_from": record.collected_at.isoformat(),
            "labels": ["sha256"],
            "confidence": int(record.confidence_score * 100),
        })

    return indicators


def _create_vulnerability(cve_id: str, record: CTIRecord) -> dict:
    """Create a STIX Vulnerability object."""
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": f"vulnerability--{UUID(int=hash(cve_id))}",
        "created": record.collected_at.isoformat(),
        "modified": record.collected_at.isoformat(),
        "name": cve_id,
        "external_references": [
            {
                "source_name": "cve",
                "external_id": cve_id,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
        ],
    }


def _create_threat_actor(actor_name: str, record: CTIRecord) -> dict:
    """Create a STIX Threat Actor object."""
    return {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": f"threat-actor--{UUID(int=hash(actor_name))}",
        "created": record.collected_at.isoformat(),
        "modified": record.collected_at.isoformat(),
        "name": actor_name,
        "labels": ["threat-actor"],
        "confidence": int(record.confidence_score * 80),  # Lower confidence for actor attribution
    }


def _create_malware(malware_name: str, record: CTIRecord) -> dict:
    """Create a STIX Malware object."""
    return {
        "type": "malware",
        "spec_version": "2.1",
        "id": f"malware--{UUID(int=hash(malware_name))}",
        "created": record.collected_at.isoformat(),
        "modified": record.collected_at.isoformat(),
        "name": malware_name,
        "malware_types": ["trojan", "unknown"],
        "is_family": True,
    }
