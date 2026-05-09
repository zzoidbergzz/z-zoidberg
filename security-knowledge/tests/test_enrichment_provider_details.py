from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from app.enrichment.providers.bgp_he import BGPHEProvider
from app.enrichment.providers.otx import OTXProvider
from app.enrichment.providers.shodan import ShodanProvider


def _patched_client(module_path: str, handler):
    real_cls = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_cls(*args, **kwargs)

    return patch(module_path, side_effect=factory)


@pytest.mark.asyncio
async def test_shodan_captures_banners_and_ssl_snis():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "org": "Example Org",
                "country_name": "United Kingdom",
                "country_code": "GB",
                "asn": "AS123",
                "ports": [443, 80],
                "hostnames": ["host.example"],
                "tags": ["vpn"],
                "data": [
                    {
                        "port": 443,
                        "transport": "tcp",
                        "product": "nginx",
                        "version": "1.25",
                        "data": "HTTP/1.1 200 OK",
                        "ssl": {
                            "cert": {
                                "subject": {
                                    "CN": "example.com",
                                    "alt_names": ["DNS:example.com", "DNS:www.example.com"],
                                }
                            }
                        },
                    }
                ],
            },
        )

    with _patched_client("app.enrichment.providers.shodan.httpx.AsyncClient", handler):
        out = await ShodanProvider(api_key="key").enrich("ip_address", "1.2.3.4")

    assert out["open_ports"] == [80, 443]
    assert out["banners"][0]["port"] == 443
    assert out["banners"][0]["ssl_snis"] == ["example.com", "www.example.com"]
    assert out["ssl_snis"] == ["example.com", "www.example.com"]


@pytest.mark.asyncio
async def test_otx_hits_are_clickable():
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/general" in url:
            return httpx.Response(
                200,
                json={
                    "pulse_info": {
                        "count": 1,
                        "pulses": [
                            {
                                "id": "pulse-1",
                                "name": "Interesting Pulse",
                                "description": "desc",
                                "author": {"username": "analyst"},
                                "modified_text": "yesterday",
                                "tags": ["tag1"],
                                "targeted_countries": ["US"],
                                "attack_ids": [{"attack_id": "T1059"}],
                                "industries": ["Tech"],
                            }
                        ],
                    },
                    "sections": ["general"],
                    "type_title": "Domain",
                    "base_indicator": {"type": "domain"},
                    "nvd_url": "",
                    "mitre_url": "",
                },
            )
        if "/url_list" in url:
            return httpx.Response(200, json={"url_list": [{"url": "https://example.com"}]})
        return httpx.Response(404)

    with _patched_client("app.enrichment.providers.otx.httpx.AsyncClient", handler):
        out = await OTXProvider(api_key="key").enrich("domain", "example.com")

    assert out["otx_info"]["indicator_url"].endswith("/indicator/domain/example.com")
    assert out["otx_pulses"][0]["url"].endswith("/pulse/pulse-1")
    assert out["search_url"].endswith("q=example.com")


@pytest.mark.asyncio
async def test_bgp_country_flag_and_peer_count():
    html = """
    <html>
      <head><title>AS123 Example</title></head>
      <body>
        <h1>AS123 Example</h1>
        <div id="description">Example ASN</div>
        <table id="asinfo">
          <tr><td>Country</td><td>GB</td></tr>
        </table>
        <table id="table_prefixes4">
          <tr><th>Prefix</th><th>Description</th></tr>
          <tr><td>1.2.3.0/24</td><td>Example net</td></tr>
        </table>
        <table id="table_peers4">
          <tr><th>ASN</th><th>Name</th></tr>
          <tr><td>AS456</td><td>Peer One</td></tr>
          <tr><td>AS789</td><td>Peer Two</td></tr>
        </table>
      </body>
    </html>
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=html)

    with _patched_client("app.enrichment.providers.bgp_he.httpx.AsyncClient", handler):
        out = await BGPHEProvider().enrich("asn", "AS123")

    assert out["country_code"] == "GB"
    assert out["country_flag"] == "🇬🇧"
    assert out["peer_count"] == 2
    assert out["peer_count_label"] == "2 peers"
