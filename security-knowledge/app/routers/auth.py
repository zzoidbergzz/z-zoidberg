from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from app.database import get_db
from app.models.auth import ApiKey
from app.auth.jwt import create_access_token
import hashlib

router = APIRouter(prefix="/auth", tags=["auth"])


class TokenRequest(BaseModel):
    api_key: str


@router.post("/token")
async def get_token(req: TokenRequest, db: AsyncSession = Depends(get_db)):
    key_hash = hashlib.sha256(req.api_key.encode()).hexdigest()
    result = await db.execute(select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.active == True))  # noqa
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    token = create_access_token({"sub": str(api_key.tenant_id), "tenant_id": str(api_key.tenant_id)})
    return {"access_token": token, "token_type": "bearer"}
