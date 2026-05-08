import pytest
from app.integrations.kev.normalizer import normalize_kev_entry


def test_normalize_kev_basic():
    entry = {
        "cveID": "CVE-2022-1234",
        "vendorProject": "Apache",
        "product": "Log4j",
        "shortDescription": "RCE via JNDI",
        "dueDate": "2022-12-31",
        "knownRansomwareCampaignUse": "Known",
    }
    result = normalize_kev_entry(entry)
    assert result["cve_id"] == "CVE-2022-1234"
    assert result["vendor"] == "Apache"
    assert result["ransomware"] is True


def test_normalize_kev_no_ransomware():
    entry = {
        "cveID": "CVE-2023-0001",
        "vendorProject": "Microsoft",
        "product": "Exchange",
        "shortDescription": "Auth bypass",
        "knownRansomwareCampaignUse": "Unknown",
    }
    result = normalize_kev_entry(entry)
    assert result["ransomware"] is False
