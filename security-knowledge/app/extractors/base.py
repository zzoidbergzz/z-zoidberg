"""Base extractor interface."""
from typing import Any, Protocol


class Extractor(Protocol):
    def extract(self, text: str) -> list[dict[str, Any]]: ...


def run_all(text: str) -> list[dict[str, Any]]:
    from app.extractors import cve_id, ip_address, url, sha256, domain
    results = []
    for extractor in [cve_id, ip_address, url, sha256, domain]:
        results.extend(extractor.extract(text))
    return results
