"""Real MCP protocol server — stdio + SSE transports.

Wraps the same tool registry used by /api/v1/mcp/call so agents that
speak the official Model Context Protocol can use every registered tool.

Transports
----------
stdio (for desktop hosts like Claude Desktop, Cursor):

    python -m app.mcp.server

SSE / HTTP (for in-process agents, mounted at /api/v1/mcp/sse):

    Import ``sse_app`` and mount it in the FastAPI app.

Sample mcp.json snippet (stdio)::

    {
      "mcpServers": {
        "security-knowledge": {
          "command": "python",
          "args": ["-m", "app.mcp.server"],
          "cwd": "/home/z/z-zoidberg/security-knowledge",
          "env": {"SK_API_KEY": "<your-api-key>"}
        }
      }
    }

OpenClaw SSE config (remote)::

    {
      "mcpServers": {
        "security-knowledge": {
          "transport": "sse",
          "url": "https://your-host/api/v1/mcp/sse",
          "headers": {"X-API-Key": "<your-api-key>"}
        }
      }
    }

Provision an API key::

    python openclaw/provision_key.py --name openclaw-mcp --scopes superadmin

The stdio server uses SK_API_KEY env var to build an AuthContext with
tenant_id from BOOTSTRAP_ADMIN_TENANT env var.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def _build_auth(tenant_id: uuid.UUID | None = None, user_id: uuid.UUID | None = None,
                api_key: str = ""):
    """Build an AuthContext for an MCP request.

    For SSE: ``tenant_id`` and ``user_id`` are taken from the validated
    ``api_keys`` row so that BYOK lookups (``resolve_user_provider_key``)
    can find the caller's per-user provider keys.
    For stdio: falls back to the bootstrap admin tenant from env.
    """
    from app.auth.dependencies import AuthContext, Scope

    if tenant_id is None:
        tenant_raw = os.environ.get("BOOTSTRAP_ADMIN_TENANT_ID") or os.environ.get(
            "BOOTSTRAP_ADMIN_TENANT", "00000000-0000-0000-0000-000000000000"
        )
        try:
            tenant_id = uuid.UUID(tenant_raw)
        except ValueError:
            tenant_id = uuid.UUID("00000000-0000-0000-0000-000000000000")

    return AuthContext(
        tenant_id=tenant_id,
        user_id=user_id,
        scopes=[Scope.read, Scope.write],
        api_key=api_key or os.environ.get("SK_API_KEY", ""),
    )


def _tool_to_mcp_schema(tool) -> dict[str, Any]:
    """Convert a McpTool to an MCP-protocol tool definition."""
    params = tool.schema or {}
    if not isinstance(params, dict) or "type" not in params:
        params = {
            "type": "object",
            "properties": {k: {"type": v} for k, v in params.items()},
        }
    return {
        "name": tool.name,
        "description": tool.description,
        "inputSchema": params,
    }


async def _make_mcp_server(tenant_id: uuid.UUID | None = None,
                           user_id: uuid.UUID | None = None):
    """Build and return a configured MCP Server instance.

    ``tenant_id`` / ``user_id`` are baked into the per-tool AuthContext so
    that downstream services (notably EnrichmentService → BYOK) can
    resolve per-user provider keys.
    """
    from mcp.server import Server
    from mcp.types import (
        TextContent,
        Tool,
    )

    import app.mcp as _mcp_pkg  # noqa: F401 — trigger tool registration
    from app.database import AsyncSessionLocal
    from app.mcp.registry import get_tool, list_tools

    server = Server("security-knowledge")

    @server.list_tools()
    async def handle_list_tools() -> list[Tool]:
        return [
            Tool(
                name=t.name,
                description=t.description,
                inputSchema=_tool_to_mcp_schema(t)["inputSchema"],
            )
            for t in list_tools()
        ]

    @server.call_tool()
    async def handle_call_tool(name: str, arguments: dict | None = None) -> list[TextContent]:
        args = arguments or {}
        tool = get_tool(name)
        if tool is None:
            return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]

        auth = _build_auth(tenant_id=tenant_id, user_id=user_id)
        async with AsyncSessionLocal() as db:
            try:
                result = await tool.fn(args, db, auth)
                return [TextContent(type="text", text=json.dumps(result, default=str))]
            except Exception as exc:  # noqa: BLE001
                logger.warning("mcp_server_tool_error", tool=name, error=str(exc))
                return [TextContent(type="text", text=json.dumps({"error": str(exc)}))]

    return server


async def run_stdio():
    """Run MCP server over stdio — for use with Claude Desktop / mcp.json."""
    from mcp.server.stdio import stdio_server

    server = await _make_mcp_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def _auth_middleware(app):
    """Wrap an ASGI app to require a valid X-API-Key on SSE/MCP requests.

    Validates the key against the ``api_keys`` table using the same
    SHA-256 lookup used by the FastAPI auth dependency. Updates
    ``last_used_at`` on success. Requests without a valid, active key
    receive 401.
    """
    async def _reject(send, status: int, body: bytes) -> None:
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                [b"content-type", b"application/json"],
                [b"www-authenticate", b'ApiKey realm="security-knowledge-mcp"'],
            ],
        })
        await send({"type": "http.response.body", "body": body})

    async def middleware(scope, receive, send):
        if scope["type"] == "lifespan":
            return await app(scope, receive, send)
        if scope["type"] not in ("http", "websocket"):
            return await app(scope, receive, send)

        headers = dict(scope.get("headers", []))
        raw_key = headers.get(b"x-api-key", b"").decode().strip()
        if not raw_key:
            auth_header = headers.get(b"authorization", b"").decode().strip()
            if auth_header.lower().startswith("bearer "):
                raw_key = auth_header.split(" ", 1)[1].strip()

        if not raw_key:
            return await _reject(
                send, 401,
                b'{"error":"X-API-Key header required for MCP access"}',
            )

        from datetime import datetime, timezone
        from app.auth.api_key import validate_api_key
        from app.database import AsyncSessionLocal

        async with AsyncSessionLocal() as db:
            api_key = await validate_api_key(db, raw_key)
            if api_key is None:
                logger.warning(
                    "mcp_auth_failed",
                    reason="invalid_or_inactive_key",
                    client=scope.get("client"),
                )
                return await _reject(
                    send, 401,
                    b'{"error":"invalid or inactive API key"}',
                )
            if api_key.expires_at is not None and api_key.expires_at < datetime.now(timezone.utc):
                logger.warning(
                    "mcp_auth_failed",
                    reason="expired_key",
                    api_key_id=str(api_key.id),
                )
                return await _reject(
                    send, 401,
                    b'{"error":"API key expired"}',
                )
            api_key.last_used_at = datetime.now(timezone.utc)
            await db.commit()
            scope.setdefault("state", {})
            scope["state"]["sk_tenant_id"] = api_key.tenant_id
            scope["state"]["sk_user_id"] = api_key.user_id
            scope["state"]["sk_api_key_id"] = api_key.id
            logger.info(
                "mcp_auth_ok",
                api_key_id=str(api_key.id),
                tenant_id=str(api_key.tenant_id),
                key_name=api_key.name,
            )

        return await app(scope, receive, send)

    return middleware


def make_sse_app():
    """Return an ASGI app exposing MCP over SSE at /sse and /messages."""
    from mcp.server.sse import SseServerTransport
    from starlette.applications import Starlette
    from starlette.routing import Mount, Route

    sse_transport = SseServerTransport("/api/v1/mcp/sse/messages")

    async def handle_sse(request):
        # Starlette Route endpoints receive a Request; SseServerTransport
        # needs the raw ASGI triple, which is exposed via request.scope /
        # request.receive / request._send.
        state = request.scope.get("state") or {}
        server = await _make_mcp_server(
            tenant_id=state.get("sk_tenant_id"),
            user_id=state.get("sk_user_id"),
        )
        async with sse_transport.connect_sse(
            request.scope, request.receive, request._send
        ) as streams:
            await server.run(
                streams[0], streams[1], server.create_initialization_options()
            )

    return _auth_middleware(Starlette(
        routes=[
            Route("/sse", endpoint=handle_sse),
            Mount("/messages", app=sse_transport.handle_post_message),
        ]
    ))


# FastAPI mount helper — call from main.py
def mount_sse(app) -> None:
    """Mount the SSE MCP app at /api/v1/mcp/sse on a FastAPI instance."""
    sse_app = make_sse_app()
    app.mount("/api/v1/mcp/sse", sse_app)
    logger.info("mcp_sse_mounted", path="/api/v1/mcp/sse")


if __name__ == "__main__":
    asyncio.run(run_stdio())
