import httpx
from app.config import settings


class NVDClient:
    BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        headers = {}
        if settings.NVD_API_KEY:
            headers["apiKey"] = settings.NVD_API_KEY
        self._headers = headers

    async def fetch_cves(self, start_index: int = 0, results_per_page: int = 100) -> dict:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                self.BASE,
                params={"startIndex": start_index, "resultsPerPage": results_per_page},
                headers=self._headers,
            )
            resp.raise_for_status()
            return resp.json()

    async def fetch_cve(self, cve_id: str) -> dict:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(self.BASE, params={"cveId": cve_id}, headers=self._headers)
            resp.raise_for_status()
            return resp.json()
