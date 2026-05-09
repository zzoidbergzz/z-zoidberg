from typing import Any

import httpx
from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.registry import register
from app.config import settings


def _norm_alt_name(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return None
    for prefix in ("DNS:", "dns:"):
        if value.startswith(prefix):
            value = value[len(prefix):].strip()
            break
    return value or None


def _extract_ssl_snis(banner: dict[str, Any]) -> list[str]:
    ssl = banner.get("ssl") or {}
    cert = ssl.get("cert") or {}
    subject = cert.get("subject") or {}
    alt_names: list[str] = []
    for source in (
        subject.get("alt_names"),
        cert.get("subject_alt_names"),
        cert.get("extensions", {}).get("subjectAltName") if isinstance(cert.get("extensions"), dict) else None,
    ):
        if isinstance(source, list):
            for item in source:
                name = _norm_alt_name(item)
                if name:
                    alt_names.append(name)
        elif isinstance(source, str):
            for chunk in source.split(","):
                name = _norm_alt_name(chunk)
                if name:
                    alt_names.append(name)
    return sorted({name for name in alt_names if name})


def _shape_banner(banner: dict[str, Any]) -> dict[str, Any]:
    ssl = banner.get("ssl") or {}
    cert = ssl.get("cert") or {}
    return {
        "port": banner.get("port"),
        "transport": banner.get("transport"),
        "product": banner.get("product"),
        "version": banner.get("version"),
        "os": banner.get("os"),
        "module": banner.get("module"),
        "timestamp": banner.get("timestamp"),
        "banner": banner.get("data") or banner.get("banner") or "",
        "title": (banner.get("http") or {}).get("title") if isinstance(banner.get("http"), dict) else None,
        "http_server": (banner.get("http") or {}).get("server") if isinstance(banner.get("http"), dict) else None,
        "ssl": bool(ssl),
        "ssl_snis": _extract_ssl_snis(banner),
        "ssl_subject_cn": (cert.get("subject") or {}).get("CN") if isinstance(cert.get("subject"), dict) else None,
    }


@register
class ShodanProvider(BaseEnrichmentProvider):
    name = "shodan"
    kind = "ip"
    supported_kinds = {"ip", "ip_address"}

    async def enrich(self, entity_kind: str, entity_value: str) -> dict:
        if entity_kind not in ("ip", "ip_address"):
            return {}
        api_key = self.api_key_override or settings.SHODAN_API_KEY
        if not api_key:
            return {}
        url = f"https://api.shodan.io/shodan/host/{entity_value}?key={api_key}"
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url)
            if resp.status_code == 404:
                return {}
            resp.raise_for_status()
            data = resp.json()
            banners = [_shape_banner(b) for b in (data.get("data") or [])[:50] if isinstance(b, dict)]
            ports = sorted({int(port) for port in data.get("ports", []) if isinstance(port, int) or str(port).isdigit()})
            ssl_snis = sorted({sni for banner in banners for sni in banner.get("ssl_snis", [])})
            return {
                "ip": entity_value,
                "org": data.get("org"),
                "country": data.get("country_name"),
                "country_code": data.get("country_code"),
                "asn": data.get("asn"),
                "ports": ports,
                "open_ports": ports,
                "banners": banners,
                "ssl_snis": ssl_snis,
                "hostnames": data.get("hostnames", []),
                "tags": data.get("tags", []),
                "data_count": len(banners),
            }
