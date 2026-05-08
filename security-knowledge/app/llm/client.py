import httpx
from app.config import settings
from app.llm.schemas import LLMRequest, LLMResponse
import structlog

logger = structlog.get_logger(__name__)


async def chat_completion(request: LLMRequest) -> LLMResponse:
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            f"{settings.LLM_BASE_URL}/chat/completions",
            json=request.model_dump(),
            headers={"Authorization": f"Bearer {settings.LLM_API_KEY}"},
        )
        resp.raise_for_status()
        data = resp.json()
        return LLMResponse(
            content=data["choices"][0]["message"]["content"],
            model=data.get("model", request.model),
            usage=data.get("usage", {}),
        )
