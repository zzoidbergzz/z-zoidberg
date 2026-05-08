#!/usr/bin/env python3
"""CLI: sync NVD CVEs."""
import asyncio
import sys
from app.integrations.nvd.client import NVDClient
from app.integrations.nvd.normalizer import normalize_cve


async def main():
    client = NVDClient()
    data = await client.get_cves()
    cves = data.get("vulnerabilities", [])
    print(f"Fetched {len(cves)} CVEs")
    for item in cves[:5]:
        norm = normalize_cve(item)
        print(norm)


if __name__ == "__main__":
    asyncio.run(main())
