from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

ui_router = APIRouter(prefix="/ui", tags=["UI"])
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent.parent / "templates"))


@ui_router.get("/", response_class=HTMLResponse)
async def ui_home(request: Request):
    return templates.TemplateResponse(request, "index.html", {"current_user": None})


@ui_router.get("/graph", response_class=HTMLResponse)
async def ui_graph(request: Request):
    return templates.TemplateResponse(request, "graph.html", {"current_user": None})


@ui_router.get("/entities", response_class=HTMLResponse)
async def ui_entities(request: Request):
    return templates.TemplateResponse(request, "entities.html", {"current_user": None})


@ui_router.get("/search", response_class=HTMLResponse)
async def ui_search(request: Request):
    return templates.TemplateResponse(request, "search.html", {"current_user": None})


@ui_router.get("/entities/{entity_id}", response_class=HTMLResponse)
async def ui_entity_detail(request: Request, entity_id: str):
    return templates.TemplateResponse(request, "entity_detail.html", {"current_user": None})


@ui_router.get("/admin", response_class=HTMLResponse)
async def ui_admin(request: Request):
    return templates.TemplateResponse(request, "admin.html", {"current_user": None})
