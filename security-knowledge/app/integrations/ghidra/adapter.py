import httpx
from app.config import settings


class GhidraAdapter:
    """Adapter for Ghidra headless analysis server."""

    def __init__(self, base_url: str | None = None):
        self.base_url = base_url or settings.GHIDRA_SERVER_URL

    async def analyze_binary(self, binary_hash: str) -> dict:
        if not self.base_url:
            return {}
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{self.base_url}/analyze",
                json={"hash": binary_hash},
            )
            resp.raise_for_status()
            return resp.json()
