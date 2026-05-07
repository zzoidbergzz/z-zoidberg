import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KEVClient:
    async def fetch(self) -> dict:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(KEV_URL)
            resp.raise_for_status()
            return resp.json()
