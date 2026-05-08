#!/usr/bin/env python3
"""Provision an API key for OpenClaw MCP access.

Usage (run from security-knowledge/):
    .venv/bin/python -m openclaw.provision_key [--name openclaw-mcp] [--scopes read,write,enrichment,watch]

Prints the raw API key to stdout exactly once. Only the SHA-256 hash is
stored in the database — the raw value cannot be recovered later.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Allow `python openclaw/provision_key.py` from repo root.
_HERE = Path(__file__).resolve().parent
_SK = _HERE.parent / "security-knowledge"
if str(_SK) not in sys.path:
    sys.path.insert(0, str(_SK))

from sqlalchemy import select  # noqa: E402

from app.auth.api_key import generate_api_key  # noqa: E402
from app.database import AsyncSessionLocal  # noqa: E402
from app.models.auth import ApiKey, User, UserRole  # noqa: E402


async def provision(name: str, scopes: str, expires_days: int | None) -> str:
    async with AsyncSessionLocal() as db:
        res = await db.execute(
            select(User).where(User.role == UserRole.admin).order_by(User.created_at.asc()).limit(1)
        )
        admin = res.scalar_one_or_none()
        if admin is None:
            raise SystemExit(
                "No admin user found. Bootstrap the service first "
                "(set BOOTSTRAP_ADMIN_EMAIL/PASSWORD in .env)."
            )

        # Refuse to reissue silently — surface duplicates.
        dup = await db.execute(
            select(ApiKey).where(ApiKey.name == name, ApiKey.tenant_id == admin.tenant_id)
        )
        existing = dup.scalar_one_or_none()
        if existing is not None and existing.active:
            raise SystemExit(
                f"An active key named {name!r} already exists for tenant "
                f"{admin.tenant_id}. Deactivate it first or pass a different --name."
            )

        raw, key_hash = generate_api_key()
        expires_at = (
            datetime.now(timezone.utc) + timedelta(days=expires_days)
            if expires_days
            else None
        )
        key = ApiKey(
            id=uuid.uuid4(),
            tenant_id=admin.tenant_id,
            user_id=admin.id,
            name=name,
            key_hash=key_hash,
            scopes=scopes,
            active=True,
            expires_at=expires_at,
        )
        db.add(key)
        await db.commit()
        return raw


def main() -> None:
    parser = argparse.ArgumentParser(description="Provision an API key for OpenClaw MCP access")
    parser.add_argument("--name", default="openclaw-mcp")
    parser.add_argument(
        "--scopes",
        default="read,write,enrichment,watch",
        help="Comma-separated scopes. Use 'superadmin' for full access (audit-only — prefer narrow scopes).",
    )
    parser.add_argument(
        "--expires-days",
        type=int,
        default=None,
        help="Optional expiry in days. Omit for non-expiring key.",
    )
    args = parser.parse_args()

    raw = asyncio.run(provision(args.name, args.scopes, args.expires_days))
    print("=" * 70)
    print("API Key (record this NOW — it will not be shown again):")
    print(raw)
    print("=" * 70)
    print("Header: X-API-Key: <key>")
    print("Endpoint: https://z.je/api/v1/mcp/sse")


if __name__ == "__main__":
    main()
