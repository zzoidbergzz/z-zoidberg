import httpx
from app.config import settings


class OpenCTIClient:
    def __init__(self):
        self.url = settings.OPENCTI_URL
        self.token = settings.OPENCTI_TOKEN

    async def query(self, gql: str, variables: dict | None = None) -> dict:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self.url}/graphql",
                json={"query": gql, "variables": variables or {}},
                headers={"Authorization": f"Bearer {self.token}"},
            )
            resp.raise_for_status()
            return resp.json()
