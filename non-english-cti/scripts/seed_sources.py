#!/usr/bin/env python3
"""Seed source catalogue — load and validate sources from YAML."""

import sys
import logging
import asyncio

sys.path.insert(0, "src")
from registry import SourceRegistry

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def seed(catalogue_path: str, top30_path: str = ""):
    """Load and validate source catalogue."""
    registry = SourceRegistry()
    count = registry.load(catalogue_path)

    if top30_path:
        top30 = SourceRegistry()
        top30_count = top30.load(top30_path)
        logger.info("Top 30 sources loaded: %d", top30_count)

    summary = registry.summary()
    print(f"Loaded {count} sources")
    print(f"Enabled: {summary['enabled']}")
    print(f"Languages: {summary['by_language']}")
    print(f"Types: {summary['by_type']}")
    print(f"Priorities: {summary['by_priority']}")


if __name__ == "__main__":
    catalogue = sys.argv[1] if len(sys.argv) > 1 else "catalogue/sources.yaml"
    top30 = sys.argv[2] if len(sys.argv) > 2 else ""
    asyncio.run(seed(catalogue, top30))
