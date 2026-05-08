"""NVD CVE enrichment provider with CISA KEV exploit-in-wild check."""
from __future__ import annotations

import time
from typing import Any

import httpx
from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.registry import register
from app.config import settings

# Simple in-process KEV cache — refreshed at most once per 6 hours.
_kev_cache: dict[str, bool] = {}
_kev_fetched_at: float = 0.0
_KEV_TTL = 6 * 3600
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def _get_kev_set() -> set[str]:
    """Return the set of CVE IDs in CISA KEV.  Caches for 6 hours."""
    global _kev_cache, _kev_fetched_at
    now = time.monotonic()
    if _kev_cache and (now - _kev_fetched_at) < _KEV_TTL:
        return set(_kev_cache.keys())
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(_KEV_URL)
            resp.raise_for_status()
            data = resp.json()
            _kev_cache = {v["cveID"]: True for v in data.get("vulnerabilities", [])}
            _kev_fetched_at = now
    except Exception:
        pass  # return stale or empty
    return set(_kev_cache.keys())


@register
class NVDProvider(BaseEnrichmentProvider):
    name = "nvd"
    kind = "cve"

    async def enrich(self, entity_kind: str, entity_value: str) -> dict[str, Any]:
        if entity_kind != "cve":
            return {}
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={entity_value}"
        headers: dict[str, str] = {}
        if settings.NVD_API_KEY:
            headers["apiKey"] = settings.NVD_API_KEY

        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {}
        cve = vulns[0].get("cve", {})
        metrics = cve.get("metrics", {})

        # CVSS — prefer v3.1 > v3.0 > v2
        cvss: dict[str, Any] = {}
        cvss_version = ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss = metrics[key][0].get("cvssData", {})
                cvss_version = key
                break

        base_score = cvss.get("baseScore")
        severity = cvss.get("baseSeverity", "")
        if not severity and base_score is not None:
            score = float(base_score)
            if score >= 9.0:
                severity = "CRITICAL"
            elif score >= 7.0:
                severity = "HIGH"
            elif score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

        # Affected products from CPE matches
        affected: list[str] = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable", False):
                        cpe_uri = cpe_match.get("criteria", "")
                        # cpe:2.3:a:vendor:product:version:... → "vendor:product version"
                        parts = cpe_uri.split(":")
                        if len(parts) >= 5:
                            vendor = parts[3].replace("_", " ")
                            product = parts[4].replace("_", " ")
                            version = parts[5] if len(parts) > 5 and parts[5] not in ("*", "-") else ""
                            label = f"{vendor} {product}" + (f" {version}" if version else "")
                            if label not in affected:
                                affected.append(label)
                        if len(affected) >= 20:
                            break

        # CISA KEV — is this CVE actively exploited in the wild?
        kev_set = await _get_kev_set()
        exploited_in_wild = entity_value.upper() in kev_set

        # CWEs
        cwes = [
            w.get("description", [{}])[0].get("value", "")
            for w in cve.get("weaknesses", [])
            if w.get("description")
        ]

        return {
            "cve_id": entity_value,
            "description": (cve.get("descriptions", [{}])[0]).get("value", ""),
            "cvss": cvss,
            "cvss_version": cvss_version,
            "base_score": base_score,
            "severity": severity,
            "published": cve.get("published"),
            "modified": cve.get("lastModified"),
            "affected_products": affected,
            "affected_count": len(affected),
            "exploited_in_wild": exploited_in_wild,
            "cisa_kev": exploited_in_wild,
            "cwes": [c for c in cwes if c],
            "nvd_link": f"https://nvd.nist.gov/vuln/detail/{entity_value.upper()}",
            "gcve_link": f"https://www.google.com/intl/en_us/about/products/safety-security/cve-portal/#cve={entity_value.upper()}",
        }
