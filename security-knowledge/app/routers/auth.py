"""Auth router: token exchange, registration, password login, user profile management."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime

import bcrypt as _bcrypt
from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import AuthContext, Scope, get_auth
from app.auth.jwt import create_access_token
from app.config import settings
from app.database import get_db
from app.models.auth import ApiKey, Tenant, TenantInviteRule, User, UserRole, UserStatus

router = APIRouter(prefix="/auth", tags=["auth"])

VALID_SECTORS = [
    "UK-General",
    "Financial-Banking",
    "Retail",
    "Infrastructure-Energy",
    "Healthcare",
    "Education",
    "Government-Defence",
    "Technology",
    "Transportation-Logistics",
    "Legal-Professional",
    "Manufacturing",
    "Media-Entertainment",
    "Charity-NGO",
]


def _personal_domains() -> set[str]:
    return {d.strip().lower() for d in settings.PERSONAL_EMAIL_DOMAINS.split(",") if d.strip()}


async def _is_invited_registration(db: AsyncSession, tenant_id: uuid.UUID, email: str) -> bool:
    domain = email.split("@")[-1]
    rows = (
        await db.execute(
            select(TenantInviteRule).where(
                TenantInviteRule.tenant_id == tenant_id,
                TenantInviteRule.active.is_(True),
                or_(
                    (TenantInviteRule.rule_type == "email") & (TenantInviteRule.rule_value == email),
                    (TenantInviteRule.rule_type == "domain") & (TenantInviteRule.rule_value == domain),
                ),
            )
        )
    ).scalars().all()
    return bool(rows)


# ──────────────────────────────────────────────────────────────────────────────
# Schemas
# ──────────────────────────────────────────────────────────────────────────────


class TokenRequest(BaseModel):
    api_key: str


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str = ""
    business_sector: str | None = "UK-General"
    tenant_name: str | None = None

    @field_validator("business_sector")
    @classmethod
    def validate_sector(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_SECTORS:
            raise ValueError(f"Invalid business_sector. Must be one of: {', '.join(VALID_SECTORS)}")
        return v


class UpdateProfileRequest(BaseModel):
    full_name: str | None = None
    business_sector: str | None = None

    @field_validator("business_sector")
    @classmethod
    def validate_sector(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_SECTORS:
            raise ValueError(f"Invalid business_sector. Must be one of: {', '.join(VALID_SECTORS)}")
        return v


class UserProfileResponse(BaseModel):
    id: str
    email: str
    full_name: str
    business_sector: str
    status: str
    role: str
    tenant_id: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ──────────────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────────────


@router.post("/token")
async def get_token(req: TokenRequest, db: AsyncSession = Depends(get_db)):
    """Exchange API key for JWT bearer token."""
    key_hash = hashlib.sha256(req.api_key.encode()).hexdigest()
    result = await db.execute(select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.active == True))  # noqa
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    if not api_key.user_id:
        raise HTTPException(status_code=403, detail="Bearer token exchange requires a user-bound API key")
    token = create_access_token({"sub": str(api_key.user_id), "tenant_id": str(api_key.tenant_id)})
    return {"access_token": token, "token_type": "bearer"}


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    """Register a new user. Account starts in 'pending' status awaiting admin approval."""
    import bcrypt

    email = req.email.lower().strip()

    # Check email uniqueness
    existing = await db.execute(select(User).where(User.email == email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")

    user_id = uuid.uuid4()

    # Resolve or create tenant
    email_domain = email.split("@")[-1]
    if req.tenant_name:
        tenant_name = req.tenant_name
        tenant_slug = tenant_name.lower().replace(" ", "-").replace(".", "-")
        t_result = await db.execute(select(Tenant).where(Tenant.slug == tenant_slug))
        tenant = t_result.scalar_one_or_none()
        if not tenant:
            tenant = Tenant(name=tenant_name, slug=tenant_slug)
            db.add(tenant)
            await db.flush()
    elif email_domain in _personal_domains():
        tenant = Tenant(
            id=user_id,
            name=email,
            slug=f"user-{user_id}",
        )
        db.add(tenant)
        await db.flush()
    else:
        tenant_name = email_domain
        tenant_slug = tenant_name.lower().replace(" ", "-").replace(".", "-")
        t_result = await db.execute(select(Tenant).where(Tenant.slug == tenant_slug))
        tenant = t_result.scalar_one_or_none()
        if not tenant:
            tenant = Tenant(name=tenant_name, slug=tenant_slug)
            db.add(tenant)
            await db.flush()

    # Hash password
    hashed = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()
    is_invited = await _is_invited_registration(db, tenant.id, email)
    status_value = UserStatus.approved if is_invited else UserStatus.pending
    approved_at = datetime.now(UTC) if is_invited else None

    user = User(
        id=user_id,
        tenant_id=tenant.id,
        email=email,
        hashed_password=hashed,
        full_name=req.full_name,
        business_sector=req.business_sector or "UK-General",
        status=status_value,
        role=UserRole.user,
        approved_at=approved_at,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    await db.commit()

    return {
        "id": str(user.id),
        "email": user.email,
        "status": user.status,
        "message": "Registration successful. Awaiting admin approval." if user.status == UserStatus.pending else "Registration successful. Account auto-approved.",
    }


@router.get("/me", response_model=UserProfileResponse)
async def get_me(auth: AuthContext = Depends(get_auth), db: AsyncSession = Depends(get_db)):
    """Return current user's profile (requires bearer token with user_id)."""
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required (use bearer token, not API key)")

    result = await db.execute(select(User).where(User.id == uuid.UUID(auth.user_id)))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return UserProfileResponse(
        id=str(user.id),
        email=user.email,
        full_name=user.full_name,
        business_sector=user.business_sector,
        status=user.status,
        role=user.role,
        tenant_id=str(user.tenant_id),
        created_at=user.created_at,
    )


@router.patch("/me", response_model=UserProfileResponse)
async def update_me(
    req: UpdateProfileRequest,
    auth: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    """Update current user's full_name and/or business_sector."""
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required (use bearer token, not API key)")

    result = await db.execute(select(User).where(User.id == uuid.UUID(auth.user_id)))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if req.full_name is not None:
        user.full_name = req.full_name
    if req.business_sector is not None:
        user.business_sector = req.business_sector

    await db.flush()
    await db.refresh(user)

    return UserProfileResponse(
        id=str(user.id),
        email=user.email,
        full_name=user.full_name,
        business_sector=user.business_sector,
        status=user.status,
        role=user.role,
        tenant_id=str(user.tenant_id),
        created_at=user.created_at,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Password login / logout (browser session cookie)
# ──────────────────────────────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


@router.post("/login")
async def login(req: LoginRequest, response: Response, db: AsyncSession = Depends(get_db)):
    """Authenticate with email + password; set an httpOnly session cookie."""
    result = await db.execute(select(User).where(User.email == req.email.lower().strip()))
    user: User | None = result.scalar_one_or_none()

    if not user or not user.hashed_password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not _bcrypt.checkpw(req.password.encode(), user.hashed_password.encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.status != UserStatus.approved:
        raise HTTPException(status_code=403, detail=f"Account status: {user.status}")
    if not user.active:
        raise HTTPException(status_code=403, detail="Account disabled")

    expire_hours = settings.ACCESS_TOKEN_EXPIRE_HOURS
    token = create_access_token(
        {
            "sub": str(user.id),
            "tenant_id": str(user.tenant_id),
            "email": user.email,
            "role": user.role,
        }
    )
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite="lax",
        max_age=expire_hours * 3600,
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": str(user.id),
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "tenant_id": str(user.tenant_id),
        },
    }


@router.post("/logout")
async def logout(response: Response):
    """Clear the session cookie."""
    response.delete_cookie(settings.SESSION_COOKIE_NAME)
    return {"message": "Logged out"}


# ──────────────────────────────────────────────────────────────────────────────
# Change password
# ──────────────────────────────────────────────────────────────────────────────


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("New password must be at least 12 characters")
        if v.lower() == v or v.upper() == v:
            raise ValueError("New password must contain mixed case")
        if not any(c.isdigit() for c in v):
            raise ValueError("New password must contain at least one digit")
        return v


@router.post("/change-password")
async def change_password(
    req: ChangePasswordRequest,
    response: Response,
    auth: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    """Verify current password, set new password, invalidate session cookie."""
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required (use bearer token, not API key)")

    result = await db.execute(select(User).where(User.id == uuid.UUID(auth.user_id)))
    user = result.scalar_one_or_none()
    if not user or not user.hashed_password:
        raise HTTPException(status_code=404, detail="User not found")

    if not _bcrypt.checkpw(req.current_password.encode(), user.hashed_password.encode()):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    if req.current_password == req.new_password:
        raise HTTPException(status_code=400, detail="New password must differ from current password")

    user.hashed_password = _bcrypt.hashpw(req.new_password.encode(), _bcrypt.gensalt()).decode()
    await db.flush()

    response.delete_cookie(settings.SESSION_COOKIE_NAME)
    return {"message": "Password changed. Please log in again."}


# ──────────────────────────────────────────────────────────────────────────────
# Bring-your-own-key (BYOK) provider key management
# ──────────────────────────────────────────────────────────────────────────────

# noqa: E402 — imports intentionally after route definitions to avoid circular
from app.auth.byok import BYOK_PROVIDERS  # noqa: E402
from app.auth.byok import encrypt_key as _encrypt_key  # noqa: E402
from app.auth.byok import key_hint as _key_hint  # noqa: E402
from app.models.auth import UserProviderKey  # noqa: E402


class ProviderKeyRequest(BaseModel):
    api_key: str

    @field_validator("api_key")
    @classmethod
    def validate_key(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 8:
            raise ValueError("API key looks too short")
        return v


class ProviderKeyResponse(BaseModel):
    provider: str
    key_hint: str | None
    created_at: datetime
    updated_at: datetime


def _ensure_provider_supported(provider: str) -> None:
    if provider not in BYOK_PROVIDERS:
        raise HTTPException(
            status_code=400,
            detail=f"Provider '{provider}' is not BYOK-enabled. Supported: {', '.join(BYOK_PROVIDERS)}",
        )


@router.get("/provider-keys", response_model=list[ProviderKeyResponse])
async def list_provider_keys(
    auth: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    """List BYOK rows for the current user. Plaintext is never returned."""
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")
    result = await db.execute(select(UserProviderKey).where(UserProviderKey.user_id == uuid.UUID(auth.user_id)))
    rows = result.scalars().all()
    return [
        ProviderKeyResponse(
            provider=r.provider,
            key_hint=r.key_hint,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )
        for r in rows
    ]


@router.get("/provider-keys/supported")
async def list_supported_providers(auth: AuthContext = Depends(get_auth)):
    """Return the list of providers that honour user-supplied keys."""
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")
    return {"providers": list(BYOK_PROVIDERS)}


@router.put("/provider-keys/{provider}", response_model=ProviderKeyResponse)
async def upsert_provider_key(
    provider: str,
    req: ProviderKeyRequest,
    auth: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    """Encrypt + store (or update) a user-supplied API key for ``provider``."""
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")
    _ensure_provider_supported(provider)

    encrypted = _encrypt_key(req.api_key)
    hint = _key_hint(req.api_key)

    result = await db.execute(
        select(UserProviderKey).where(
            UserProviderKey.user_id == uuid.UUID(auth.user_id),
            UserProviderKey.provider == provider,
        )
    )
    row = result.scalar_one_or_none()
    if row is None:
        row = UserProviderKey(
            user_id=uuid.UUID(auth.user_id),
            tenant_id=uuid.UUID(auth.tenant_id),
            provider=provider,
            encrypted_key=encrypted,
            key_hint=hint,
        )
        db.add(row)
    else:
        row.encrypted_key = encrypted
        row.key_hint = hint
    await db.flush()
    await db.refresh(row)

    return ProviderKeyResponse(
        provider=row.provider,
        key_hint=row.key_hint,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.delete("/provider-keys/{provider}", status_code=204)
async def delete_provider_key(
    provider: str,
    auth: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    """Remove a user's BYOK row; subsequent enrichments fall back to the system key."""
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")
    _ensure_provider_supported(provider)

    result = await db.execute(
        select(UserProviderKey).where(
            UserProviderKey.user_id == uuid.UUID(auth.user_id),
            UserProviderKey.provider == provider,
        )
    )
    row = result.scalar_one_or_none()
    if row is not None:
        await db.delete(row)
        await db.flush()
    return Response(status_code=204)


# ──────────────────────────────────────────────────────────────────────────────
# Personal API keys (the keys this user uses to call the API / MCP)
# ──────────────────────────────────────────────────────────────────────────────


class ApiKeyMetadata(BaseModel):
    id: str
    name: str
    scopes: str
    active: bool
    created_at: datetime | None = None
    last_used_at: datetime | None = None
    expires_at: datetime | None = None
    key_hint: str  # last 4 chars of key_hash, for visual disambiguation only


class ApiKeyCreated(ApiKeyMetadata):
    api_key: str  # plaintext — shown ONCE at creation/rotation


def _api_key_metadata(k: ApiKey) -> ApiKeyMetadata:
    return ApiKeyMetadata(
        id=str(k.id),
        name=k.name,
        scopes=k.scopes or "",
        active=k.active,
        created_at=k.created_at,
        last_used_at=k.last_used_at,
        expires_at=k.expires_at,
        key_hint=(k.key_hash or "")[-4:],
    )


def _parse_requested_scopes(raw_scopes: str) -> set[Scope]:
    tokens = [t.strip().lower() for t in (raw_scopes or "").replace(",", " ").split() if t.strip()]
    if not tokens:
        return {Scope.read}
    requested: set[Scope] = set()
    for token in tokens:
        try:
            requested.add(Scope(token))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Unknown scope: {token}") from exc
    return requested


def _scope_string(scopes: set[Scope]) -> str:
    return " ".join(scope.value for scope in Scope if scope in scopes)


def _validated_scope_string(raw_scopes: str, auth: AuthContext) -> str:
    requested = _parse_requested_scopes(raw_scopes)
    for scope in requested:
        if not auth.has_scope(scope):
            raise HTTPException(
                status_code=403,
                detail=f"Cannot grant scope '{scope.value}' you do not already have",
            )
    return _scope_string(requested)


@router.get("/api-keys", response_model=list[ApiKeyMetadata])
async def list_my_api_keys(
    auth: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")
    result = await db.execute(
        select(ApiKey)
        .where(ApiKey.user_id == uuid.UUID(auth.user_id))
        .order_by(ApiKey.created_at.desc())
    )
    return [_api_key_metadata(k) for k in result.scalars().all()]


class ApiKeyCreateRequest(BaseModel):
    name: str = "personal"
    scopes: str = "read write enrichment watch"


@router.post("/api-keys", response_model=ApiKeyCreated, status_code=201)
async def create_my_api_key(
    body: ApiKeyCreateRequest,
    auth: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    """Create a new personal API key. Plaintext returned once — store it now."""
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")

    from app.auth.api_key import generate_api_key

    raw, key_hash = generate_api_key()
    scope_string = _validated_scope_string(body.scopes, auth)
    key = ApiKey(
        tenant_id=uuid.UUID(auth.tenant_id),
        user_id=uuid.UUID(auth.user_id),
        name=body.name[:255] or "personal",
        scopes=scope_string,
        key_hash=key_hash,
        active=True,
    )
    db.add(key)
    await db.flush()
    await db.refresh(key)
    meta = _api_key_metadata(key)
    return ApiKeyCreated(api_key=raw, **meta.model_dump())


@router.post("/api-keys/{key_id}/rotate", response_model=ApiKeyCreated)
async def rotate_my_api_key(
    key_id: str,
    auth: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    """Rotate a key: deactivate the old one and issue a new one with the same name+scopes."""
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")
    try:
        kid = uuid.UUID(key_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid key id")

    result = await db.execute(
        select(ApiKey).where(ApiKey.id == kid, ApiKey.user_id == uuid.UUID(auth.user_id))
    )
    old = result.scalar_one_or_none()
    if not old:
        raise HTTPException(status_code=404, detail="key not found")

    from app.auth.api_key import generate_api_key

    raw, key_hash = generate_api_key()
    new = ApiKey(
        tenant_id=old.tenant_id,
        user_id=old.user_id,
        name=old.name,
        scopes=old.scopes,
        key_hash=key_hash,
        active=True,
    )
    old.active = False
    db.add(new)
    await db.flush()
    await db.refresh(new)
    meta = _api_key_metadata(new)
    return ApiKeyCreated(api_key=raw, **meta.model_dump())


@router.delete("/api-keys/{key_id}", status_code=204)
async def revoke_my_api_key(
    key_id: str,
    auth: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")
    try:
        kid = uuid.UUID(key_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid key id")
    result = await db.execute(
        select(ApiKey).where(ApiKey.id == kid, ApiKey.user_id == uuid.UUID(auth.user_id))
    )
    key = result.scalar_one_or_none()
    if key:
        key.active = False
        await db.flush()
    return Response(status_code=204)
