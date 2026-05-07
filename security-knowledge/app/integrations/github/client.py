import httpx
from app.config import settings

GRAPHQL_URL = "https://api.github.com/graphql"

ADVISORIES_QUERY = """
query($after: String) {
  securityAdvisories(first: 100, after: $after) {
    pageInfo { hasNextPage endCursor }
    nodes {
      ghsaId severity summary description publishedAt updatedAt
      identifiers { type value }
      vulnerabilities(first: 10) {
        nodes { package { name ecosystem } vulnerableVersionRange firstPatchedVersion { identifier } }
      }
    }
  }
}
"""


class GitHubAdvisoryClient:
    async def fetch_page(self, after: str | None = None) -> dict:
        headers = {"Authorization": f"bearer {settings.GITHUB_TOKEN}"} if settings.GITHUB_TOKEN else {}
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                GRAPHQL_URL,
                json={"query": ADVISORIES_QUERY, "variables": {"after": after}},
                headers=headers,
            )
            resp.raise_for_status()
            return resp.json()
