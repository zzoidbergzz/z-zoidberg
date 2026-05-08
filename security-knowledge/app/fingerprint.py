from __future__ import annotations
from datetime import datetime, timezone
from fastapi import Request

def request_ip(request: Request) -> str:
    headers = request.headers
    return (
        headers.get("cf-connecting-ip")
        or headers.get("x-real-ip")
        or headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )

def server_side_fingerprint(request: Request) -> dict:
    headers = dict(request.headers)
    return {
        "network": {
            "ip": request_ip(request),
            "remote_port": request.client.port if request.client else None,
            "http_version": request.scope.get("http_version"),
            "method": request.method,
            "path": str(request.url),
            "scheme": request.url.scheme,
        },
        "headers": {
            "raw": headers,
            "user_agent": headers.get("user-agent"),
            "accept": headers.get("accept"),
            "accept_language": headers.get("accept-language"),
            "accept_encoding": headers.get("accept-encoding"),
            "dnt": headers.get("dnt"),
            "sec_gpc": headers.get("sec-gpc"),
            "connection": headers.get("connection"),
        },
        "client_hints": {
            "sec_ch_ua": headers.get("sec-ch-ua"),
            "sec_ch_ua_mobile": headers.get("sec-ch-ua-mobile"),
            "sec_ch_ua_platform": headers.get("sec-ch-ua-platform"),
            "sec_ch_ua_full_version_list": headers.get("sec-ch-ua-full-version-list"),
            "sec_ch_ua_arch": headers.get("sec-ch-ua-arch"),
            "sec_ch_prefers_color_scheme": headers.get("sec-ch-prefers-color-scheme"),
        },
        "sec_fetch": {
            "dest": headers.get("sec-fetch-dest"),
            "mode": headers.get("sec-fetch-mode"),
            "site": headers.get("sec-fetch-site"),
            "user": headers.get("sec-fetch-user"),
        },
        "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
