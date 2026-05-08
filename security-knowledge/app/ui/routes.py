from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.config import settings
from app.ui.deps import get_template_user

templates = Jinja2Templates(directory=str(Path(__file__).parent.parent.parent / "templates"))

ui_router = APIRouter(tags=["UI"])

PROTECTED = ["/", "/graph", "/entities", "/search", "/admin", "/investigation", "/fp", "/settings"]


def _authed(request: Request) -> bool:
    return bool(request.cookies.get(settings.SESSION_COOKIE_NAME))


def _login_redirect(path: str) -> RedirectResponse:
    return RedirectResponse(url=f"/login?next={quote(path)}", status_code=307)


@ui_router.get("/", response_class=HTMLResponse)
async def ui_home(request: Request):
    if not _authed(request):
        return _login_redirect("/")
    return templates.TemplateResponse(request, "index.html", {"current_user": get_template_user(request)})


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
    return templates.TemplateResponse(request, "admin.html", {"current_user": get_template_user(request)})


@ui_router.get("/settings", response_class=HTMLResponse)
async def ui_settings(request: Request):
    if not _authed(request):
        return _login_redirect("/settings")
    return templates.TemplateResponse(request, "settings.html", {"current_user": get_template_user(request)})


# Legacy /ui/* → root redirects (backward compat)
@ui_router.get("/ui", include_in_schema=False)
@ui_router.get("/ui/", include_in_schema=False)
async def ui_legacy_root():
    return RedirectResponse(url="/", status_code=301)


@ui_router.get("/ui/{path:path}", include_in_schema=False)
async def ui_legacy_path(path: str):
    return RedirectResponse(url=f"/{path}", status_code=301)
