"""Security Knowledge FastAPI application."""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from app.config import settings
from app.observability.logging import configure_logging
from app.observability.tracing import configure_tracing
from app.database import engine

from app.routers.health import router as health_router
from app.routers.metrics import router as metrics_router
from app.routers.auth import router as auth_router
from app.routers.entities import router as entities_router
from app.routers.claims import router as claims_router
from app.routers.evidence import router as evidence_router
from app.routers.search import router as search_router
from app.routers.ingest import router as ingest_router
from app.routers.enrich import router as enrich_router
from app.routers.graph import router as graph_router
from app.routers.stix import router as stix_router
from app.routers.webhooks import router as webhooks_router
from app.routers.audit import router as audit_router
from app.routers.digests import router as digests_router
from app.routers.detections import router as detections_router
from app.routers.sources import router as sources_router
from app.routers.mcp import router as mcp_router
from app.routers.admin import router as admin_router
from app.routers.pingback import router as pingback_router
from app.routers.sectors import router as sectors_router
from app.routers.mitre import router as mitre_router
from app.taxii.server import taxii_router
from app.graphql.schema import graphql_router


configure_logging()
if settings.OTEL_EXPORTER_OTLP_ENDPOINT:
    configure_tracing(settings.SERVICE_NAME, settings.OTEL_EXPORTER_OTLP_ENDPOINT)


@asynccontextmanager
async def lifespan(app: FastAPI):
    import asyncio
    from app.services import mitre_attack
    asyncio.create_task(mitre_attack.preload_if_cached())
    yield
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
app.include_router(graphql_router, prefix="/graphql")

# Static files (UI)
templates_path = Path(__file__).parent.parent / "templates"
if templates_path.exists():
    from app.ui.routes import ui_router
    app.include_router(ui_router)
