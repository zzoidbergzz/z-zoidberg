from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional
import uuid
from app.database import get_db
from app.auth.dependencies import require_read, require_write
from app.models.webhooks import WebhookSubscription

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


class WebhookCreate(BaseModel):
    url: str
    event_types: list[str] = []
    secret: Optional[str] = None


class WebhookOut(BaseModel):
    id: uuid.UUID
    url: str
    active: bool
    tenant_id: uuid.UUID
    model_config = {"from_attributes": True}


@router.get("/", response_model=list[WebhookOut])
async def list_webhooks(
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(require_read),
):
    result = await db.execute(
        select(WebhookSubscription).where(WebhookSubscription.tenant_id == auth["tenant_id"])
    )
    return result.scalars().all()


@router.post("/", response_model=WebhookOut, status_code=201)
async def create_webhook(
    body: WebhookCreate,
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(require_write),
):
    wh = WebhookSubscription(
        tenant_id=auth["tenant_id"],
        url=body.url,
        filters={"event_types": body.event_types},
        secret=body.secret,
    )
    db.add(wh)
    await db.flush()
    await db.refresh(wh)
    return wh
