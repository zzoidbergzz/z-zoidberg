"""MCP router — tool discovery and dispatch."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

import app.mcp  # noqa: F401 — trigger tool registration side-effects
from app.auth.dependencies import AuthContext, Scope, get_auth
from app.database import get_db
from app.mcp.registry import get_tool, list_tools

router = APIRouter(prefix="/mcp", tags=["MCP"])


class ToolCall(BaseModel):
    tool: str
    args: dict = {}


@router.post("/call")
async def call_tool(
    body: ToolCall,
    auth: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    auth.require_scope(Scope.read)

    tool = get_tool(body.tool)
    if tool is None:
        return {"error": {"code": "unknown_tool", "message": f"Unknown tool: {body.tool}"}}

    if tool.scope == "write":
        auth.require_scope(Scope.write)

    try:
        result = await tool.fn(body.args, db, auth)
    except Exception as exc:  # noqa: BLE001
        return {"error": {"code": "tool_error", "message": str(exc)}}

    return result


@router.get("/tools")
async def list_tools_endpoint(auth: AuthContext = Depends(get_auth)):
    auth.require_scope(Scope.read)
    tools = list_tools()
    return {
        "tools": [t.name for t in tools],
        "tool_schemas": [
            {
                "name": t.name,
                "description": t.description,
                "scope": t.scope,
                "parameters": t.schema,
            }
            for t in tools
        ],
    }
