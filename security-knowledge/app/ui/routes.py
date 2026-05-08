from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.config import settings

templates = Jinja2Templates(directory=str(Path(__file__).parent.parent.parent / "templates"))

# Root-level UI router — no prefix, serves pages at natural paths
ui_router = APIRouter(tags=["UI"])


@ui_router.get("/", response_class=HTMLResponse)
async def ui_home(request: Request):
    cookie = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not cookie:
        return RedirectResponse(url="/login", status_code=307)
    return templates.TemplateResponse(request, "index.html", {"current_user": None})


@ui_router.get("/graph", response_class=HTMLResponse)
async def ui_graph(request: Request):
    return templates.TemplateResponse(request, "graph.html", {"current_user": None})


@ui_router.get("/entities", response_class=HTMLResponse)
async def ui_entities(request: Request):
    return templates.TemplateResponse(request, "entities.html", {"current_user": None})


@ui_router.get("/entities/{entity_id}", response_class=HTMLResponse)
async def ui_entity_detail(request: Request, entity_id: str):
    return templates.TemplateResponse(request, "entity_detail.html", {"current_user": None})


@ui_router.get("/search", response_class=HTMLResponse)
async def ui_search(request: Request):
    return templates.TemplateResponse(request, "search.html", {"current_user": None})


@ui_router.get("/admin", response_class=HTMLResponse)
async def ui_admin(request: Request):
    return templates.TemplateResponse(request, "admin.html", {"current_user": None})


# Legacy /ui/* → root redirects (backward compat)
@ui_router.get("/ui", include_in_schema=False)
@ui_router.get("/ui/", include_in_schema=False)
async def ui_legacy_root():
    return RedirectResponse(url="/", status_code=301)


@ui_router.get("/ui/{path:path}", include_in_schema=False)
async def ui_legacy_path(path: str):
    return RedirectResponse(url=f"/{path}", status_code=301)
