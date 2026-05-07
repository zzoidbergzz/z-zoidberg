import httpx
from app.config import settings


class TAXIIClient:
    def __init__(self, url: str, username: str = "", password: str = ""):
        self.url = url.rstrip("/")
        self.auth = (username, password) if username else None

    async def get_collections(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(
                f"{self.url}/collections/",
                headers={"Accept": "application/taxii+json;version=2.1"},
                auth=self.auth,
            )
            resp.raise_for_status()
            return resp.json().get("collections", [])

    async def get_objects(self, collection_id: str, added_after: str | None = None) -> dict:
        params = {}
        if added_after:
            params["added_after"] = added_after
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.get(
                f"{self.url}/collections/{collection_id}/objects/",
                headers={"Accept": "application/taxii+json;version=2.1"},
                params=params,
                auth=self.auth,
            )
            resp.raise_for_status()
            return resp.json()
