from __future__ import annotations
import re
from ipaddress import ip_address, ip_network
from app.lookup.normalizer import normalize_indicator

def classify_input(raw: str) -> dict[str, str]:
    raw = normalize_indicator(raw)
    normalized_domain = raw.rstrip(".").lower()
    if not raw:
        return {"type": "empty", "value": ""}
    try:
        addr = ip_address(raw)
        return {"type": "ip", "value": str(addr)}
    except ValueError:
        pass
    try:
        net = ip_network(raw, strict=False)
        return {"type": "cidr", "value": str(net)}
    except ValueError:
        pass
    if re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", raw):
        return {"type": "email", "value": raw.lower()}
    if re.match(r"^https?://", raw, re.IGNORECASE):
        return {"type": "url", "value": raw}
    if re.match(r"^[a-fA-F0-9]{64}$", raw):
        return {"type": "sha256", "value": raw.lower()}
    if re.match(r"^[a-fA-F0-9]{40}$", raw):
        return {"type": "sha1", "value": raw.lower()}
    if re.match(r"^[a-fA-F0-9]{32}$", raw):
        return {"type": "md5", "value": raw.lower()}
    if re.match(r"^AS\d+$", raw, re.IGNORECASE):
        return {"type": "asn", "value": raw.upper()}
    cleaned_phone = re.sub(r"[\s\-().]", "", raw)
    if re.match(r"^\+?\d{7,15}$", cleaned_phone):
        return {"type": "phone", "value": cleaned_phone}
    if re.match(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", normalized_domain):
        return {"type": "domain", "value": normalized_domain}
    if re.match(r"^@?[a-zA-Z0-9_]{3,30}$", raw):
        return {"type": "username", "value": raw.lstrip("@").lower()}
    return {"type": "unknown", "value": raw}
