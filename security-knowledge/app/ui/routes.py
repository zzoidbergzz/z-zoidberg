from pathlib import Path
from urllib.parse import quote

import structlog
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import text as sql_text

from app.config import settings
from app.database import AsyncSessionLocal
from app.observability.metrics import record_exception_counter
from app.ui.deps import get_template_user

templates = Jinja2Templates(directory=str(Path(__file__).parent.parent.parent / "templates"))

ui_router = APIRouter(tags=["UI"])
logger = structlog.get_logger(__name__)

PROTECTED = ["/", "/graph", "/entities", "/search", "/admin", "/investigation", "/fp", "/settings", "/claims", "/digests", "/breaches"]


def _authed(request: Request) -> bool:
    return bool(request.cookies.get(settings.SESSION_COOKIE_NAME))


def _login_redirect(path: str) -> RedirectResponse:
    return RedirectResponse(url=f"/login?next={quote(path)}", status_code=307)


@ui_router.get("/", response_class=HTMLResponse)
async def ui_home(request: Request):
    if not _authed(request):
        return _login_redirect("/")
    return templates.TemplateResponse(
        request,
        "index.html",
        {"current_user": get_template_user(request), "stats": {}},
    )


@ui_router.get("/graph", response_class=HTMLResponse)
async def ui_graph(request: Request):
    if not _authed(request):
        return _login_redirect("/graph")
    return templates.TemplateResponse(request, "graph.html", {"current_user": get_template_user(request)})


@ui_router.get("/entities", response_class=HTMLResponse)
async def ui_entities(request: Request):
    if not _authed(request):
        return _login_redirect("/entities")
    return templates.TemplateResponse(request, "entities.html", {"current_user": get_template_user(request)})


@ui_router.get("/entities/{entity_id}", response_class=HTMLResponse)
async def ui_entity_detail(request: Request, entity_id: str):
    if not _authed(request):
        return _login_redirect(f"/entities/{entity_id}")

    # Smart redirect: an id passed here may actually point at a corpus_documents
    # row (CVE/GCVE/Exploit-DB) or a claim — both common when search results
    # link the wrong UUID. Look it up and 302 to the right detail page so the
    # user never sees a bare 404. Entity rows pass straight through to the
    # template (which handles missing entities itself).
    import re as _re
    if _re.fullmatch(r"[0-9a-fA-F-]{36}", entity_id):
        try:
            async with AsyncSessionLocal() as db:
                row = (await db.execute(sql_text(
                    "SELECT id::text FROM entities WHERE id = :id LIMIT 1"
                ), {"id": entity_id})).first()
                if row is None:
                    cd = (await db.execute(sql_text(
                        "SELECT corpus, external_id FROM corpus_documents WHERE id = :id LIMIT 1"
                    ), {"id": entity_id})).first()
                    if cd:
                        corpus, ext = cd
                        if corpus in ("cve", "gcve"):
                            return RedirectResponse(url=f"/cve/{ext}", status_code=302)
                        if corpus == "exploitdb":
                            return RedirectResponse(url=f"/exploit/{ext.replace('EDB-', '')}", status_code=302)
                    cl = (await db.execute(sql_text(
                        "SELECT entity_id::text FROM claims WHERE id = :id AND entity_id IS NOT NULL LIMIT 1"
                    ), {"id": entity_id})).first()
                    if cl and cl[0]:
                        return RedirectResponse(url=f"/entities/{cl[0]}", status_code=302)
        except Exception:
            logger.exception("ui_entity_detail_redirect_probe_failed", entity_id=entity_id)
            record_exception_counter("ui.entity_detail_redirect")

    return templates.TemplateResponse(request, "entity_detail.html", {"current_user": get_template_user(request)})


@ui_router.get("/search", response_class=HTMLResponse)
async def ui_search(request: Request):
    if not _authed(request):
        return _login_redirect("/search")
    return templates.TemplateResponse(request, "search.html", {"current_user": get_template_user(request)})


@ui_router.get("/admin", response_class=HTMLResponse)
async def ui_admin(request: Request):
    if not _authed(request):
        return _login_redirect("/admin")
    current_user = get_template_user(request)
    if not current_user or current_user.get("role") not in {"admin", "superadmin"}:
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse(request, "admin.html", {"current_user": current_user})


@ui_router.get("/ingest", response_class=HTMLResponse)
async def ui_ingest(request: Request):
    if not _authed(request):
        return _login_redirect("/ingest")
    return templates.TemplateResponse(request, "ingest.html", {"current_user": get_template_user(request)})


@ui_router.get("/claims", response_class=HTMLResponse)
async def ui_claims(request: Request):
    if not _authed(request):
        return _login_redirect("/claims")
    return templates.TemplateResponse(request, "claims.html", {"current_user": get_template_user(request)})


@ui_router.get("/digests", response_class=HTMLResponse)
async def ui_digests(request: Request):
    if not _authed(request):
        return _login_redirect("/digests")
    return templates.TemplateResponse(request, "digests.html", {"current_user": get_template_user(request)})


@ui_router.get("/cve/{cve_id}", response_class=HTMLResponse)
async def ui_cve_detail(request: Request, cve_id: str):
    if not _authed(request):
        return _login_redirect(f"/cve/{cve_id}")
    return templates.TemplateResponse(
        request,
        "cve_detail.html",
        {"current_user": get_template_user(request), "cve_id": cve_id.upper()},
    )


@ui_router.get("/exploit/{edb_id}", response_class=HTMLResponse)
async def ui_exploit_detail(request: Request, edb_id: str):
    if not _authed(request):
        return _login_redirect(f"/exploit/{edb_id}")
    eid = edb_id.upper()
    if not eid.startswith("EDB-"):
        eid = f"EDB-{eid}"
    return templates.TemplateResponse(
        request,
        "exploit_detail.html",
        {"current_user": get_template_user(request), "edb_id": eid},
    )


@ui_router.get("/settings", response_class=HTMLResponse)
async def ui_settings(request: Request):
    if not _authed(request):
        return _login_redirect("/settings")
    return templates.TemplateResponse(request, "settings.html", {"current_user": get_template_user(request)})


@ui_router.get("/breaches/{claim_id}", response_class=HTMLResponse)
async def ui_breach_summary(request: Request, claim_id: str):
    if not _authed(request):
        return _login_redirect(f"/breaches/{claim_id}")
    return templates.TemplateResponse(
        request,
        "breach_summary.html",
        {"current_user": get_template_user(request), "claim_id": claim_id},
    )


@ui_router.get("/onion/view", response_class=HTMLResponse)
async def ui_onion_view(request: Request):
    if not _authed(request):
        return _login_redirect("/onion/view")
    return templates.TemplateResponse(
        request,
        "onion_view.html",
        {"current_user": get_template_user(request)},
    )


# Legacy /ui/* → root redirects (backward compat)
@ui_router.get("/ui", include_in_schema=False)
@ui_router.get("/ui/", include_in_schema=False)
async def ui_legacy_root():
    return RedirectResponse(url="/", status_code=301)


@ui_router.get("/ui/{path:path}", include_in_schema=False)
async def ui_legacy_path(path: str):
    return RedirectResponse(url=f"/{path}", status_code=301)
