from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.auth.dependencies import require_read, AuthContext
from app.auth.byok import resolve_user_provider_key
from app.config import settings
import httpx

router = APIRouter(prefix="/ask", tags=["ask"])


class AskRequest(BaseModel):
    question: str
    context: str = ""
    model: str = "claude-3-5-haiku-20241022"


class AskResponse(BaseModel):
    answer: str
    model: str


@router.post("/", response_model=AskResponse)
async def ask_ai(
    req: AskRequest,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_read),
):
    # Resolve API key: user BYOK first, then system key
    api_key = await resolve_user_provider_key(db, auth.user_id, "anthropic")
    if not api_key:
        api_key = getattr(settings, "ANTHROPIC_API_KEY", None)
    if not api_key:
        raise HTTPException(400, "No Anthropic API key configured. Add yours in Settings → Provider API Keys.")

    messages = []
    if req.context:
        messages.append({"role": "user", "content": f"Context:\n{req.context}\n\nQuestion: {req.question}"})
    else:
        messages.append({"role": "user", "content": req.question})

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": req.model, "max_tokens": 1024, "messages": messages},
        )
    if not resp.is_success:
        err = resp.json().get("error", {})
        raise HTTPException(502, f"Anthropic error: {err.get('message', resp.text)}")
    data = resp.json()
    answer = data["content"][0]["text"]
    return AskResponse(answer=answer, model=data["model"])
