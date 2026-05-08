"""Helpers for resolving the current user from a session cookie inside HTML routes.

The HTML pages render Jinja templates that gate the logout button and admin
nav on a ``current_user`` template variable. Without this helper every UI
route was passing ``current_user: None`` so the logout button never rendered.
"""
from __future__ import annotations

from typing import Optional

from fastapi import Request
from jose import JWTError

from app.auth.jwt import decode_token
from app.config import settings


def get_template_user(request: Request) -> Optional[dict]:
    """Decode the ``sk_session`` cookie if present and return a small dict
    suitable for template rendering. Returns ``None`` when not authenticated
    or when the token cannot be decoded.

    The returned dict deliberately exposes only non-sensitive fields:
    ``email``, ``role``, ``user_id``, ``tenant_id``.
    """
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not token:
        return None
    try:
        payload = decode_token(token)
    except JWTError:
        return None
    if not payload.get("sub"):
        return None
    return {
        "user_id": payload.get("sub"),
        "tenant_id": payload.get("tenant_id"),
        "email": payload.get("email", ""),
        "role": payload.get("role", "user"),
    }
