from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import uuid
from app.database import get_db
from app.auth.dependencies import require_read, require_write
from app.models.detections import DetectionRule
from app.detections.schemas import DetectionRuleCreate, DetectionRuleOut

router = APIRouter(prefix="/detections", tags=["detections"])


@router.get("/", response_model=list[DetectionRuleOut])
async def list_rules(
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(require_read),
):
    result = await db.execute(
        select(DetectionRule).where(DetectionRule.tenant_id == auth["tenant_id"])
    )
    return result.scalars().all()


@router.post("/", response_model=DetectionRuleOut, status_code=201)
async def create_rule(
    body: DetectionRuleCreate,
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(require_write),
):
    rule = DetectionRule(tenant_id=auth["tenant_id"], **body.model_dump())
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    return rule
