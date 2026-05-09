"""CVE extraction and enrichment."""

from __future__ import annotations
import re
import logging
from typing import Optional
from datetime import datetime

import httpx

logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def extract_cves(text: str) -> list[str]:
    """Extract CVE identifiers from text."""
    if not text:
        return []
    cves = set(CVE_PATTERN.findall(text))
    return sorted(cves, key=lambda c: (int(c.split("-")[1]), int(c.split("-")[2])))


async def enrich_cve(cve_id: str, api_key: Optional[str] = None) -> Optional[dict]:
    """Enrich a CVE with details from NVD API.

    Returns dict with: description, cvss_v3, cwe, cpe, references, published, last_modified.
    """
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                NVD_API_BASE,
                params={"cveId": cve_id},
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None

        cve_data = vulnerabilities[0].get("cve", {})

        # Extract description
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Extract CVSS v3
        metrics = cve_data.get("metrics", {})
        cvss_v3 = None
        for key in ("cvssMetricV31", "cvssMetricV30"):
            if key in metrics and metrics[key]:
                cvss_data = metrics[key][0].get("cvssData", {})
                cvss_v3 = {
                    "score": cvss_data.get("baseScore"),
                    "severity": cvss_data.get("baseSeverity"),
                    "vector": cvss_data.get("vectorString"),
                }
                break

        # Extract CWE
        weaknesses = cve_data.get("weaknesses", [])
        cwes = []
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    cwes.append(desc.get("value", ""))

        # Extract CPE
        configurations = cve_data.get("configurations", [])
        cpes = []
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpes.append(cpe_match.get("criteria", ""))

        # Extract references
        references = []
        for ref in cve_data.get("references", []):
            references.append({
                "url": ref.get("url", ""),
                "source": ref.get("source", ""),
                "tags": ref.get("tags", []),
            })

        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_v3": cvss_v3,
            "cwes": cwes,
            "cpes": cpes[:20],  # Limit
            "references": references[:10],
            "published": cve_data.get("published", ""),
            "last_modified": cve_data.get("lastModified", ""),
        }

    except Exception as e:
        logger.warning("CVE enrichment failed for %s: %s", cve_id, e)
        return None
