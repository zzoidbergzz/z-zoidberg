"""MCP tool: ask the LLM a question (uses caller's BYOK Anthropic key)."""

from __future__ import annotations

import httpx
import structlog

from app.auth.byok import resolve_user_provider_key
from app.config import settings
from app.mcp.registry import register_tool

logger = structlog.get_logger(__name__)


async def _ask_question(args: dict, db, auth) -> dict:
    question = (args.get("question") or "").strip()
    if not question:
        return {"error": "question is required"}
    context = args.get("context") or ""
    model = args.get("model") or "claude-3-5-haiku-20241022"

    api_key = await resolve_user_provider_key(db, auth.user_id, "anthropic")
    if not api_key:
        api_key = getattr(settings, "ANTHROPIC_API_KEY", None)
    if not api_key:
        return {
            "error": "no_api_key",
            "message": "No Anthropic API key. Configure one in Settings → Provider API Keys.",
        }

    content = f"Context:\n{context}\n\nQuestion: {question}" if context else question
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": int(args.get("max_tokens", 1024)),
                "messages": [{"role": "user", "content": content}],
            },
        )
    if not resp.is_success:
        try:
            err = resp.json().get("error", {})
        except Exception:
            err = {"message": resp.text[:500]}
        logger.warning("mcp_ask_anthropic_error", status=resp.status_code, error=err)
        return {"error": "anthropic_error", "status": resp.status_code, "detail": err}

    data = resp.json()
    return {
        "answer": data["content"][0]["text"],
        "model": data.get("model", model),
        "stop_reason": data.get("stop_reason"),
        "usage": data.get("usage", {}),
    }


register_tool(
    name="ask_question",
    fn=_ask_question,
    schema={
        "type": "object",
        "required": ["question"],
        "properties": {
            "question": {"type": "string", "description": "The question to ask"},
            "context": {"type": "string", "description": "Optional preamble context"},
            "model": {"type": "string", "description": "Anthropic model id"},
            "max_tokens": {"type": "integer", "description": "Max output tokens (default 1024)"},
        },
    },
    description="Ask a free-form question. Uses your BYOK Anthropic key if registered, else platform key.",
    scope="read",
)
