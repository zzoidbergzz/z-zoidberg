#!/usr/bin/env python3
"""Provision an API key for OpenClaw MCP access.

Usage:
    python -m openclaw.provision_key [--name openclaw-mcp] [--scopes superadmin]

Prints the raw API key to stdout. The key hash is stored in the database.
"""
from __future__ import annotations

import argparse
import asyncio
import uuid

from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.models.auth import ApiKey, User, UserRole


async def provision(name: str, scopes: str) -> str:
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(User).where(User.role == UserRole.admin).limit(1))
        admin = res.scalar_one_or_none()
        if admin is None:
            raise SystemExit("No admin user found. Bootstrap the service first (set BOOTSTRAP_ADMIN_EMAIL/PASSWORD in .env).")

        key = ApiKey(
            id=uuid.uuid4(),
            tenant_id=admin.tenant_id,
            user_id=admin.id,
            name=name,
            key_hash="",  # set by set_raw_key
            scopes=scopes,
            active=True,
        )
        raw = await key.set_raw_key()
        db.add(key)
        await db.commit()
        return raw


def main() -> None:
    parser = argparse.ArgumentParser(description="Provision an API key for OpenClaw MCP access")
    parser.add_argument("--name", default="openclaw-mcp", help="Key name (default: openclaw-mcp)")
    parser.add_argument("--scopes", default="superadmin", help="Comma-separated scopes (default: superadmin)")
    args = parser.parse_args()

    raw = asyncio.run(provision(args.name, args.scopes))
    print(f"API Key: {raw}")
    print(f"Add to OpenClaw MCP config as X-API-Key header value.")


if __name__ == "__main__":
    main()
