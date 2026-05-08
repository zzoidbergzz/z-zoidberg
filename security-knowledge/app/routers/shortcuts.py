from __future__ import annotations
import secrets
import json
from pathlib import Path
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.auth.dependencies import get_auth_optional, AuthContext
from app.database import get_db
from app.fingerprint import request_ip, server_side_fingerprint
from datetime import datetime, timezone

router = APIRouter(tags=["shortcuts"])

_templates_dir = Path(__file__).parent.parent.parent / "templates"
_templates = Jinja2Templates(directory=str(_templates_dir)) if _templates_dir.exists() else None


def _utcnow_str() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@router.get("/ip")
@router.get("/i")
@router.get("/myip")
async def get_ip(request: Request):
    return PlainTextResponse(request_ip(request))


@router.get("/r")
async def rickroll():
    return RedirectResponse("https://www.youtube.com/watch?v=dQw4w9WgXcQ")


@router.get("/ua")
async def get_user_agent(request: Request):
    return PlainTextResponse(request.headers.get("user-agent", "unknown"))


@router.get("/headers")
async def get_headers(request: Request):
    return PlainTextResponse("\n".join(f"{k}: {v}" for k, v in request.headers.items()))


@router.get("/fp", response_class=HTMLResponse)
@router.get("/fingerprint", response_class=HTMLResponse)
async def fingerprint_page(request: Request, auth: AuthContext | None = Depends(get_auth_optional)):
    server_data = server_side_fingerprint(request)
    context = {
        "server": server_data,
        "current_user": {"user_id": auth.user_id, "email": auth.user_email} if auth else None,
    }
    if _templates is not None:
        try:
            return _templates.TemplateResponse(request, "fingerprint.html", context)
        except Exception:
            pass
    # Fallback: return JSON if no template available
    from fastapi.responses import JSONResponse
    return JSONResponse(context)


@router.post("/fp/collect")
async def fingerprint_collect(
    request: Request,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext | None = Depends(get_auth_optional),
):
    client_data = await request.json()
    server_data = server_side_fingerprint(request)
    combined = {"server": server_data, "client": client_data, "generated_at": _utcnow_str()}
    event_id = secrets.token_hex(16)
    await db.execute(text("""
        INSERT INTO fingerprint_events (id, user_id, tenant_id, ip_address, user_agent, fingerprint_hash, path, server_data, client_data, combined_data, created_at)
        VALUES (:id, :user_id, :tenant_id, :ip, :ua, :fhash, :path, :server_data::jsonb, :client_data::jsonb, :combined::jsonb, now())
    """), {
        "id": event_id,
        "user_id": auth.user_id if auth else None,
        "tenant_id": auth.tenant_id if auth else None,
        "ip": request_ip(request),
        "ua": request.headers.get("user-agent"),
        "fhash": client_data.get("hash"),
        "path": str(request.url),
        "server_data": json.dumps(server_data),
        "client_data": json.dumps(client_data),
        "combined": json.dumps(combined),
    })
    await db.commit()
    combined["event_id"] = event_id
    return combined


@router.get("/investigation", response_class=HTMLResponse, include_in_schema=False)
@router.get("/investigation/", response_class=HTMLResponse, include_in_schema=False)
async def investigation_page(request: Request):
    if _templates is not None:
        return _templates.TemplateResponse(request, "investigation.html", {"current_user": None, "request": request})
    return HTMLResponse("<html><body><p>Templates not found</p></body></html>", 503)
