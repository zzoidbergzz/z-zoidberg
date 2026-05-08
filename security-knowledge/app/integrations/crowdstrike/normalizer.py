"""Normalizers for CrowdStrike Falcon API responses.

Each function takes a raw resource dict from the Falcon API and returns
a plain dict in the internal SecurityKnowledge format.
"""
from __future__ import annotations

from typing import Any


def normalize_report(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Falcon Intel report resource."""
    return {
        "source": "crowdstrike_intel",
        "external_id": raw.get("id"),
        "title": raw.get("name") or raw.get("title", ""),
        "description": raw.get("description", ""),
        "url": raw.get("url", ""),
        "published_at": raw.get("created_date") or raw.get("last_modified_date"),
        "updated_at": raw.get("last_modified_date"),
        "severity": raw.get("rating", {}).get("name", "") if isinstance(raw.get("rating"), dict) else "",
        "tags": [t.get("value", "") for t in raw.get("tags", []) if isinstance(t, dict)],
        "actors": [a.get("slug", a.get("name", "")) for a in raw.get("actors", []) if isinstance(a, dict)],
        "target_industries": [
            i.get("value", "") for i in raw.get("target_industries", []) if isinstance(i, dict)
        ],
        "target_countries": [
            c.get("value", "") for c in raw.get("target_countries", []) if isinstance(c, dict)
        ],
        "raw": raw,
    }


def normalize_actor(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Falcon Intel actor (threat actor) resource."""
    return {
        "source": "crowdstrike_intel",
        "external_id": raw.get("id"),
        "name": raw.get("name", ""),
        "slug": raw.get("slug", ""),
        "description": raw.get("description", ""),
        "short_description": raw.get("short_description", ""),
        "first_activity": raw.get("first_activity_date"),
        "last_activity": raw.get("last_activity_date"),
        "active": raw.get("active", False),
        "origin": raw.get("origins", [{}])[0].get("value", "") if raw.get("origins") else "",
        "target_industries": [
            i.get("value", "") for i in raw.get("target_industries", []) if isinstance(i, dict)
        ],
        "target_countries": [
            c.get("value", "") for c in raw.get("target_countries", []) if isinstance(c, dict)
        ],
        "motivations": [m.get("value", "") for m in raw.get("motivations", []) if isinstance(m, dict)],
        "kill_chain": raw.get("kill_chain", {}),
        "raw": raw,
    }


def normalize_indicator(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Falcon Intel indicator (IOC) resource."""
    return {
        "source": "crowdstrike_intel",
        "external_id": raw.get("id"),
        "indicator": raw.get("indicator", ""),
        "kind": raw.get("type", ""),  # domain, ip_address, hash_md5, etc.
        "malicious_confidence": raw.get("malicious_confidence", ""),
        "published_at": raw.get("published_date"),
        "last_updated": raw.get("last_updated"),
        "kill_chains": raw.get("kill_chains", []),
        "malware_families": raw.get("malware_families", []),
        "threat_types": raw.get("threat_types", []),
        "actors": raw.get("actors", []),
        "vulnerabilities": raw.get("vulnerabilities", []),
        "labels": [
            {"name": lbl.get("name", ""), "created_at": lbl.get("created_on")}
            for lbl in raw.get("labels", [])
            if isinstance(lbl, dict)
        ],
        "ip_address_types": raw.get("ip_address_types", []),
        "raw": raw,
    }


def normalize_spotlight_vulnerability(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Spotlight vulnerability resource."""
    cve = raw.get("cve") or {}
    return {
        "source": "crowdstrike_spotlight",
        "external_id": raw.get("id"),
        "cve_id": cve.get("id", ""),
        "hostname": (raw.get("host_info") or {}).get("hostname", ""),
        "aid": (raw.get("host_info") or {}).get("device_id", ""),
        "status": raw.get("status", ""),
        "severity": cve.get("severity", ""),
        "cvss_score": cve.get("base_score"),
        "description": cve.get("description", ""),
        "remediation": (raw.get("remediation") or {}).get("entities", []),
        "created_at": raw.get("created_timestamp"),
        "updated_at": raw.get("updated_timestamp"),
        "raw": raw,
    }
