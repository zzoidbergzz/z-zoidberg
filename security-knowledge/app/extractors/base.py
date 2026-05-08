"""Base extractor interface."""
from typing import Any, Protocol


class Extractor(Protocol):
    def extract(self, text: str) -> list[dict[str, Any]]: ...


def run_all(text: str) -> list[dict[str, Any]]:
    from app.extractors import (
        actor,
        cpe,
        cve_id,
        cwe,
        domain,
        ip_address,
        malware,
        sha256,
        technique,
        url,
    )

    results: list[dict[str, Any]] = []
    for extractor in (
        cve_id,
        ip_address,
        url,
        sha256,
        domain,
        technique,
        cwe,
        cpe,
        actor,
        malware,
    ):
        results.extend(extractor.extract(text))
    return results

