# TOOLS.md
## gh-pages
- Site: https://mzje.github.io/z-zoidberg/
- Branch: `gh-pages` on `mzje/z-zoidberg`
- NEVER publish sensitive/personal/high-risk. Get approval first.

## SearXNG
- Local: http://localhost:8888 (container: searx)
- `curl -s "http://localhost:8888/search?q=QUERY&format=json"`

## CrowdStrike Falcon MCP
- Repo: https://github.com/CrowdStrike/falcon-mcp
- SDK: https://github.com/CrowdStrike/falconpy (crowdstrike-falconpy on PyPI)
- MCP server exposing Falcon APIs: detections, intel, hosts, IOC, Spotlight, NGSIEM, RTR
- Config: `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, `FALCON_BASE_URL`
- Run: `uvx falcon-mcp` or `uvx falcon-mcp --modules detections,intel,hosts`
- MCP config: see `security-knowledge/mcp-tool-manifest.json` under `mcp_servers`
