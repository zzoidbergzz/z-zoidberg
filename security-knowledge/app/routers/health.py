from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.database import get_db
from app.config import settings

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check():
    return {"status": "ok"}


@router.get("/healthz")
async def healthz():
    return {"ok": True, "version": settings.APP_VERSION}


@router.get("/health/db")
async def health_db(db: AsyncSession = Depends(get_db)):
    await db.execute(text("SELECT 1"))
    return {"status": "ok", "db": "connected"}
