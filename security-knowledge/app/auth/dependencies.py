"""Auth dependencies and RBAC scope enforcement."""
from __future__ import annotations
from enum import Enum
from typing import Annotated
import structlog
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.auth.api_key import validate_api_key
from app.auth.jwt import decode_token
from app.config import settings
from app.database import get_db
from app.models.auth import ApiKey, User, UserStatus

logger = structlog.get_logger(__name__)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


class Scope(str, Enum):
    read = "read"
    write = "write"
    review = "review"
    admin = "admin"
    enrichment = "enrichment"
    watch = "watch"
    contact = "contact"
    export = "export"
    superadmin = "superadmin"


ADMIN_SCOPES = {Scope.read, Scope.write, Scope.review, Scope.admin, Scope.enrichment, Scope.watch, Scope.contact, Scope.export}
USER_SCOPES = {Scope.read, Scope.write, Scope.enrichment, Scope.watch, Scope.contact}
SUPERADMIN_SCOPES = set(Scope)


def _parse_scopes(raw: str) -> set[Scope]:
    result: set[Scope] = set()
    for token in raw.replace(",", " ").split():
        try:
            result.add(Scope(token))
        except ValueError:
            pass
    if Scope.superadmin in result:
        return SUPERADMIN_SCOPES
    return result


class AuthContext:
    def __init__(self, tenant_id: str, scopes: set[Scope], user_id: str | None = None, user_email: str | None = None, auth_type: str = "api_key") -> None:
        self.tenant_id = tenant_id
        self.scopes = scopes
        self.user_id = user_id
        self.user_email = user_email
        self.auth_type = auth_type

    def has_scope(self, scope: Scope) -> bool:
        return scope in self.scopes or Scope.superadmin in self.scopes

    def require_scope(self, scope: Scope) -> None:
        if not self.has_scope(scope):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Scope '{scope.value}' required")


async def _resolve_api_key(raw_key: str, db: AsyncSession) -> AuthContext | None:
    record: ApiKey | None = await validate_api_key(db, raw_key)
    if record is None or not record.active:
        return None
    return AuthContext(tenant_id=str(record.tenant_id), scopes=_parse_scopes(record.scopes), user_id=str(record.user_id) if record.user_id else None, auth_type="api_key")


async def _resolve_bearer(token: str, db: AsyncSession) -> AuthContext | None:
    try:
        payload = decode_token(token)
    except JWTError:
        return None
    user_id = payload.get("sub")
    tenant_id = payload.get("tenant_id")
    if not user_id or not tenant_id:
        return None
    result = await db.execute(select(User).where(User.id == user_id))
    user: User | None = result.scalar_one_or_none()
    if user is None or not user.active or user.status != UserStatus.approved:
        return None
    scopes = ADMIN_SCOPES if user.role == "admin" else USER_SCOPES
    return AuthContext(tenant_id=tenant_id, scopes=scopes, user_id=str(user.id), user_email=user.email, auth_type="bearer")


async def get_auth(
    request: Request,
    raw_api_key: str | None = Security(api_key_header),
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> AuthContext:
    # 1. X-API-Key header
    if raw_api_key:
        ctx = await _resolve_api_key(raw_api_key, db)
        if ctx:
            return ctx
    # 2. Authorization: Bearer token
    if credentials:
        ctx = await _resolve_bearer(credentials.credentials, db)
        if ctx:
            return ctx
    # 3. Session cookie (browser UI)
    cookie_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if cookie_token:
        ctx = await _resolve_bearer(cookie_token, db)
        if ctx:
            return ctx
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")


async def get_auth_optional(
    request: Request,
    raw_api_key: str | None = Security(api_key_header),
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> AuthContext | None:
    try:
        return await get_auth(request, raw_api_key, credentials, db)
    except HTTPException:
        return None


def require_scope(scope: Scope):
    async def _dep(auth: AuthContext = Depends(get_auth)) -> AuthContext:
        auth.require_scope(scope)
        return auth
    return _dep


require_read = require_scope(Scope.read)
require_write = require_scope(Scope.write)
require_review = require_scope(Scope.review)
require_admin = require_scope(Scope.admin)
require_enrichment = require_scope(Scope.enrichment)
require_watch = require_scope(Scope.watch)
require_contact = require_scope(Scope.contact)
require_export = require_scope(Scope.export)
