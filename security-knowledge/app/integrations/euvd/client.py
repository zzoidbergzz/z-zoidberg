import httpx
from app.config import settings


class EUVDClient:
    BASE = "https://euvd.enisa.europa.eu/api"

    async def fetch_vulnerabilities(self, page: int = 1) -> dict:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(f"{self.BASE}/vulnerabilities", params={"page": page})
            resp.raise_for_status()
            return resp.json()
