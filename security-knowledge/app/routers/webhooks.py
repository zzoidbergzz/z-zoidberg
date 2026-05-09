from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, Field
from typing import Optional
import uuid
from app.database import get_db
from app.auth.dependencies import AuthContext, require_read, require_write
from app.fetcher import validate_url_for_fetch
from app.models.webhooks import WebhookSubscription

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def _tenant_id_from_auth(auth: AuthContext | dict) -> str:
    tenant_id = getattr(auth, "tenant_id", None)
    if tenant_id is None and isinstance(auth, dict):
        tenant_id = auth.get("tenant_id")
    if tenant_id is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return str(tenant_id)


class WebhookCreate(BaseModel):
    url: str
    event_types: list[str] = Field(default_factory=list)
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
    auth: AuthContext | dict = Depends(require_read),
):
    result = await db.execute(
        select(WebhookSubscription).where(WebhookSubscription.tenant_id == _tenant_id_from_auth(auth))
    )
    return result.scalars().all()


@router.post("/", response_model=WebhookOut, status_code=201)
async def create_webhook(
    body: WebhookCreate,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext | dict = Depends(require_write),
):
    validation_error = await validate_url_for_fetch(body.url)
    if validation_error:
        raise HTTPException(status_code=422, detail=f"Invalid webhook URL: {validation_error}")
    wh = WebhookSubscription(
        tenant_id=_tenant_id_from_auth(auth),
        url=body.url,
        filters={"event_types": body.event_types},
        secret=body.secret,
    )
    db.add(wh)
    await db.flush()
    await db.refresh(wh)
    return wh
