from typing import Annotated
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from jose import JWTError

from app.database import get_db
from app.auth.api_key import validate_api_key
from app.auth.jwt import decode_token
from app.models.auth import Tenant, ApiKey


api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_tenant_from_api_key(
    api_key: str | None = Security(api_key_header),
    db: AsyncSession = Depends(get_db),
) -> ApiKey | None:
    if api_key is None:
        return None
    key_record = await validate_api_key(db, api_key)
    return key_record


async def get_current_tenant_from_bearer(
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> dict | None:
    if credentials is None:
        return None
    try:
        payload = decode_token(credentials.credentials)
        return payload
    except JWTError:
        return None


async def require_auth(
    api_key_record: ApiKey | None = Depends(get_current_tenant_from_api_key),
    bearer_payload: dict | None = Depends(get_current_tenant_from_bearer),
) -> dict:
    if api_key_record is not None:
        return {"tenant_id": str(api_key_record.tenant_id), "scopes": api_key_record.scopes, "auth_type": "api_key"}
    if bearer_payload is not None:
        return bearer_payload
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")


async def require_read(auth: dict = Depends(require_auth)) -> dict:
    return auth


async def require_write(auth: dict = Depends(require_auth)) -> dict:
    scopes = auth.get("scopes", "")
    if "write" not in scopes and not auth.get("is_superuser"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Write scope required")
    return auth
