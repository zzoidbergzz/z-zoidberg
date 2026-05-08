import httpx
from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.registry import register
from app.config import settings


@register
class NVDProvider(BaseEnrichmentProvider):
    name = "nvd"
    kind = "cve"

    async def enrich(self, entity_kind: str, entity_value: str) -> dict:
        if entity_kind != "cve":
            return {}
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={entity_value}"
        headers = {}
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
            cvss = {}
            for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if k in metrics and metrics[k]:
                    cvss = metrics[k][0].get("cvssData", {})
                    break
            return {
                "cve_id": entity_value,
                "description": (cve.get("descriptions", [{}])[0]).get("value", ""),
                "cvss": cvss,
                "published": cve.get("published"),
                "modified": cve.get("lastModified"),
            }
