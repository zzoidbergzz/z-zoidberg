import pytest
from app.integrations.nvd.normalizer import normalize_cve


def test_normalize_cve_basic():
    raw = {
        "cve": {
            "id": "CVE-2024-1234",
            "descriptions": [{"lang": "en", "value": "A critical vulnerability"}],
            "metrics": {},
            "references": [],
        }
    }
    result = normalize_cve(raw)
    assert result["cve_id"] == "CVE-2024-1234"
    assert "description" in result


def test_normalize_cve_missing_fields():
    raw = {"cve": {"id": "CVE-2024-0000"}}
    result = normalize_cve(raw)
    assert result["cve_id"] == "CVE-2024-0000"
