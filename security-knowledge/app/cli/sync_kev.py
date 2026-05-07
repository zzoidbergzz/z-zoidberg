#!/usr/bin/env python3
"""CLI: sync CISA KEV."""
import asyncio
from app.integrations.kev.client import KEVClient
from app.integrations.kev.normalizer import normalize_kev_entry


async def main():
    client = KEVClient()
    data = await client.get_catalog()
    entries = data.get("vulnerabilities", [])
    print(f"Fetched {len(entries)} KEV entries")
    for entry in entries[:5]:
        print(normalize_kev_entry(entry))


if __name__ == "__main__":
    asyncio.run(main())
