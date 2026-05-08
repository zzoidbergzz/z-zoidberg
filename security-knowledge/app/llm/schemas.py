from pydantic import BaseModel
from typing import Any


class LLMMessage(BaseModel):
    role: str
    content: str


class LLMRequest(BaseModel):
    model: str
    messages: list[LLMMessage]
    temperature: float = 0.0
    max_tokens: int = 2048


class LLMResponse(BaseModel):
    content: str
    model: str
    usage: dict[str, Any] = {}
