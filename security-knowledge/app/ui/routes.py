from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

ui_router = APIRouter(prefix="/ui", tags=["UI"])
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent.parent / "templates"))


@ui_router.get("/", response_class=HTMLResponse)
async def ui_home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@ui_router.get("/graph", response_class=HTMLResponse)
async def ui_graph(request: Request):
    return templates.TemplateResponse("graph.html", {"request": request})


@ui_router.get("/entities", response_class=HTMLResponse)
async def ui_entities(request: Request):
    return templates.TemplateResponse("entities.html", {"request": request})
