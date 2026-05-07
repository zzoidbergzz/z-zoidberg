import pytest
from app.extractors.cve_id import extract as extract_cve
from app.extractors.ip_address import extract as extract_ip
from app.extractors.url import extract as extract_url
from app.extractors.sha256 import extract as extract_sha256
from app.extractors.domain import extract as extract_domain
from app.extractors.base import run_all


def test_cve_extractor_basic():
    results = extract_cve("Found CVE-2024-1234 in the wild")
    assert len(results) == 1
    assert results[0]["value"] == "CVE-2024-1234"
    assert results[0]["kind"] == "cve"


def test_cve_extractor_multiple():
    results = extract_cve("CVE-2023-9999 and CVE-2024-0001 are related")
    assert len(results) == 2


def test_cve_extractor_case_insensitive():
    results = extract_cve("cve-2024-1234")
    assert len(results) == 1


def test_ip_extractor_basic():
    results = extract_ip("Attacker from 192.168.1.1 was detected")
    assert len(results) == 1
    assert results[0]["value"] == "192.168.1.1"
    assert results[0]["kind"] == "ip"


def test_ip_extractor_multiple():
    results = extract_ip("Traffic from 10.0.0.1 to 8.8.8.8")
    assert len(results) == 2


def test_ip_extractor_no_match():
    results = extract_ip("No IP address here")
    assert results == []


def test_url_extractor():
    results = extract_url("See https://evil.com/payload and http://c2.example.org/cmd")
    assert len(results) == 2
    assert any("evil.com" in r["value"] for r in results)


def test_sha256_extractor():
    hash_val = "a" * 64
    results = extract_sha256(f"Hash: {hash_val}")
    assert len(results) == 1
    assert results[0]["kind"] == "hash"


def test_sha256_short_hash_no_match():
    results = extract_sha256("abc123def456")
    assert results == []


def test_domain_extractor():
    results = extract_domain("Connected to malware.example.com for C2")
    assert any("example.com" in r["value"] or "malware.example.com" in r["value"] for r in results)


def test_run_all_combined():
    text = "CVE-2024-9876 at 1.2.3.4 and https://evil.org/path"
    results = run_all(text)
    kinds = {r["kind"] for r in results}
    assert "cve" in kinds
    assert "ip" in kinds
    assert "url" in kinds
