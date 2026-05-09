"""Security Knowledge FastAPI application."""
from contextlib import asynccontextmanager
from pathlib import Path

import bcrypt as _bcrypt
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import settings
from app.database import engine
from app.graphql.schema import graphql_router
from app.observability.logging import configure_logging
from app.observability.tracing import configure_tracing
from app.routers.admin import router as admin_router
from app.routers.audit import router as audit_router
from app.routers.auth import router as auth_router
from app.routers.claims import router as claims_router
from app.routers.detections import router as detections_router
from app.routers.digests import router as digests_router
from app.routers.enrich import router as enrich_router
from app.routers.entities import router as entities_router
from app.routers.evidence import router as evidence_router
from app.routers.export import router as export_router
from app.routers.capabilities import router as capabilities_router
from app.routers.import_corpus import router as import_corpus_router
from app.routers.graph import router as graph_router
from app.routers.shortcuts import router as shortcuts_router
from app.routers.ticker import router as ticker_router
from app.routers.ask import router as ask_router
from app.routers.lookup import router as lookup_router
from app.routers.health import router as health_router
from app.routers.ingest import router as ingest_router
from app.routers.mcp import router as mcp_router
from app.routers.metrics import router as metrics_router
from app.routers.mitre import router as mitre_router
from app.routers.pingback import router as pingback_router
from app.routers.search import router as search_router
from app.routers.sectors import router as sectors_router
from app.routers.sources import router as sources_router
from app.routers.stix import router as stix_router
from app.routers.webhooks import router as webhooks_router
from app.taxii.server import taxii_router

configure_logging()
if settings.OTEL_EXPORTER_OTLP_ENDPOINT:
    configure_tracing(settings.SERVICE_NAME, settings.OTEL_EXPORTER_OTLP_ENDPOINT)


async def _bootstrap_admin() -> None:
    """Create or ensure the bootstrap admin user exists (m@z.je)."""
    if not settings.BOOTSTRAP_ADMIN_EMAIL or not settings.BOOTSTRAP_ADMIN_PASSWORD:
        return
    import uuid
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession
    from app.database import AsyncSessionLocal
    from app.models.auth import User, UserStatus, UserRole, Tenant

    async with AsyncSessionLocal() as db:
        # Ensure tenant exists
        tenant_res = await db.execute(select(Tenant).where(Tenant.slug == settings.BOOTSTRAP_ADMIN_TENANT))
        tenant = tenant_res.scalar_one_or_none()
        if not tenant:
            tenant = Tenant(id=uuid.uuid4(), name=settings.BOOTSTRAP_ADMIN_NAME, slug=settings.BOOTSTRAP_ADMIN_TENANT, active=True)
            db.add(tenant)
            await db.flush()

        # Upsert admin user
        user_res = await db.execute(select(User).where(User.email == settings.BOOTSTRAP_ADMIN_EMAIL.lower()))
        user = user_res.scalar_one_or_none()
        pw_hash = _bcrypt.hashpw(settings.BOOTSTRAP_ADMIN_PASSWORD.encode(), _bcrypt.gensalt()).decode()
        if not user:
            user = User(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                email=settings.BOOTSTRAP_ADMIN_EMAIL.lower(),
                full_name=settings.BOOTSTRAP_ADMIN_NAME,
                hashed_password=pw_hash,
                status=UserStatus.approved,
                role=UserRole.admin,
                active=True,
            )
            db.add(user)
        else:
            # Always keep password in sync with .env for easy rotation
            user.hashed_password = pw_hash
            user.status = UserStatus.approved
            user.role = UserRole.admin
            user.active = True
        await db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    import asyncio

    from app.browser_pool import browser_pool
    from app.services import mitre_attack
    asyncio.create_task(mitre_attack.preload_if_cached())
    await browser_pool.start()  # no-op if PLAYWRIGHT_ENABLED=false
    await _bootstrap_admin()
    yield
    await browser_pool.stop()
    await engine.dispose()


app = FastAPI(
    title="Security Knowledge",
    description="Threat intelligence knowledge base with enrichment and graph capabilities",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Templates ──────────────────────────────────────────────────────────────────
_templates_dir = Path(__file__).parent.parent / "templates"
_templates = Jinja2Templates(directory=str(_templates_dir)) if _templates_dir.exists() else None

# ── Public browser pages ───────────────────────────────────────────────────────
PUBLIC_PATHS = {"/login", "/register", "/health", "/api", "/fp", "/ip", "/ua", "/headers", "/static", "/favicon.ico", "/pending"}


def _is_public(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") for p in PUBLIC_PATHS)


@app.get("/login", include_in_schema=False, response_class=HTMLResponse)
async def login_page(request: Request, error: str = ""):
    if _templates is None:
        return HTMLResponse("<html><body><p>Templates not found</p></body></html>", status_code=503)
    return _templates.TemplateResponse(request, "login.html", {"current_user": None, "error": error})


@app.get("/register", include_in_schema=False, response_class=HTMLResponse)
async def register_page(request: Request):
    if _templates is None:
        return HTMLResponse("<html><body><p>Templates not found</p></body></html>", status_code=503)
    return _templates.TemplateResponse(request, "register.html", {"current_user": None})


@app.get("/pending", include_in_schema=False, response_class=HTMLResponse)
async def pending_page(request: Request):
    if _templates is None:
        return HTMLResponse("<html><body><p>Pending approval</p></body></html>")
    return _templates.TemplateResponse(request, "pending.html", {"current_user": None})


# Routers
app.include_router(health_router)
app.include_router(metrics_router)
app.include_router(auth_router, prefix="/api/v1")
app.include_router(entities_router, prefix="/api/v1")
app.include_router(claims_router, prefix="/api/v1")
app.include_router(evidence_router, prefix="/api/v1")
app.include_router(search_router, prefix="/api/v1")
app.include_router(ingest_router, prefix="/api/v1")
app.include_router(enrich_router, prefix="/api/v1")
app.include_router(graph_router, prefix="/api/v1")
app.include_router(stix_router, prefix="/api/v1")
app.include_router(webhooks_router, prefix="/api/v1")
app.include_router(audit_router, prefix="/api/v1")
app.include_router(digests_router, prefix="/api/v1")
app.include_router(detections_router, prefix="/api/v1")
app.include_router(sources_router, prefix="/api/v1")
app.include_router(mcp_router, prefix="/api/v1")
app.include_router(taxii_router)
app.include_router(admin_router, prefix="/api/v1")
app.include_router(pingback_router, prefix="/api/v1")
app.include_router(sectors_router, prefix="/api/v1")
app.include_router(mitre_router, prefix="/api/v1")
app.include_router(export_router, prefix="/api/v1")
app.include_router(capabilities_router, prefix="/api/v1")
app.include_router(import_corpus_router, prefix="/api/v1")
app.include_router(graphql_router, prefix="/graphql")
app.include_router(shortcuts_router)
app.include_router(lookup_router, prefix="/api/v1")
app.include_router(ask_router, prefix="/api/v1")
app.include_router(ticker_router, prefix="/api/v1")

# Static files (UI)
templates_path = Path(__file__).parent.parent / "templates"
if templates_path.exists():
    from app.ui.routes import ui_router
    app.include_router(ui_router)

# Serve /static from mzje/z-style static directory if present
_static_dir = Path(__file__).parent.parent / "static"
if _static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

# Mount real MCP SSE transport at /api/v1/mcp/sse
from app.mcp.server import mount_sse as _mount_mcp_sse  # noqa: E402
_mount_mcp_sse(app)

