from fastapi import APIRouter, Depends
from pydantic import BaseModel
from app.auth.dependencies import require_read

router = APIRouter(prefix="/mcp", tags=["MCP"])


class ToolCall(BaseModel):
    tool: str
    args: dict = {}


@router.post("/call")
async def call_tool(body: ToolCall, auth: dict = Depends(require_read)):
    if body.tool == "enrich_entity":
        from app.mcp.tools.enrich_entity import EnrichEntityInput, enrich_entity_tool
        inp = EnrichEntityInput(tenant_id=str(auth["tenant_id"]), **body.args)
        result = await enrich_entity_tool(inp)
        return result.model_dump()
    return {"error": f"Unknown tool: {body.tool}"}


@router.get("/tools")
async def list_tools(auth: dict = Depends(require_read)):
    return {"tools": ["enrich_entity"]}
