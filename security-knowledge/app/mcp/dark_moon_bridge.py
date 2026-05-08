"""Dark-Moon MCP bridge.

Spawns the upstream Dark-Moon stdio MCP server (https://github.com/ASCIT31/Dark-Moon)
as a subprocess, discovers its tools via JSON-RPC ``initialize`` + ``tools/list``,
and registers each one in our local MCP registry with the ``dm_`` prefix.

Only active when ``DARK_MOON_ENABLED=true`` (default: false).

Dark-Moon requires a running Docker container named ``darkmoon`` (see upstream docs).
Each tool call spawns a fresh subprocess session for isolation and simplicity.

License note: Dark-Moon is GPLv3. We invoke it as a subprocess (external tool),
which does not create a derivative work. Our own code remains under its own licence.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any

import structlog
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DARK_MOON_ENABLED: bool = os.getenv("DARK_MOON_ENABLED", "false").lower() in ("1", "true", "yes")

# Local path to the ``mcp/`` directory inside a cloned Dark-Moon repository.
# E.g. /opt/dark-moon/mcp  (must contain src/server.py)
DARK_MOON_PATH: Path = Path(os.getenv("DARK_MOON_PATH", "/opt/dark-moon/mcp"))

# Python interpreter to use when spawning Dark-Moon.  Falls back to a venv
# at DARK_MOON_PATH/../.venv if present, otherwise the current interpreter.
_dm_venv_python = DARK_MOON_PATH.parent / ".venv" / "bin" / "python"
DARK_MOON_PYTHON: str = os.getenv(
    "DARK_MOON_PYTHON",
    str(_dm_venv_python) if _dm_venv_python.exists() else sys.executable,
)

# Docker / runtime configuration forwarded to Dark-Moon subprocess.
_DARK_MOON_ENV_OVERRIDES: dict[str, str] = {
    k: v
    for k, v in {
        "DOCKER_CONTAINER_NAME": os.getenv("DARK_MOON_DOCKER_CONTAINER", "darkmoon"),
        "DOCKER_TIMEOUT": os.getenv("DARK_MOON_DOCKER_TIMEOUT", "300"),
        "OUTPUT_DIR": os.getenv("DARK_MOON_OUTPUT_DIR", "/opt/darkmoon/out"),
        "TEMP_DIR": os.getenv("DARK_MOON_TEMP_DIR", "/var/darkmoon/tmp"),
        "DEFAULT_THREADS": os.getenv("DARK_MOON_THREADS", "25"),
        "DEFAULT_RATE_LIMIT": os.getenv("DARK_MOON_RATE_LIMIT", "1000"),
    }.items()
    if v is not None
}

# Names of all registered dm_* tools (populated at startup).
registered_dm_tools: list[str] = []

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_TOOL_CALL_TIMEOUT = 300  # seconds — Dark-Moon scans can be long-running


async def _invoke_dark_moon_tool(tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Spawn a Dark-Moon subprocess and call one tool via MCP JSON-RPC.

    A fresh subprocess is used per call so that each invocation is fully
    isolated (e.g. independent session IDs, no shared state).
    """
    env = {**os.environ, **_DARK_MOON_ENV_OVERRIDES}

    server_params = StdioServerParameters(
        command=DARK_MOON_PYTHON,
        args=["src/server.py"],
        cwd=str(DARK_MOON_PATH),
        env=env,
    )

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await asyncio.wait_for(session.initialize(), timeout=30)
                result = await asyncio.wait_for(
                    session.call_tool(tool_name, args or {}),
                    timeout=_TOOL_CALL_TIMEOUT,
                )
                # Flatten MCP content list to a single dict/string.
                if result.isError:
                    return {"error": _extract_text(result.content)}
                return {"result": _extract_text(result.content)}
    except asyncio.TimeoutError:
        logger.warning("dark_moon_tool_timeout", tool=tool_name)
        return {"error": f"tool timed out after {_TOOL_CALL_TIMEOUT}s"}
    except Exception as exc:  # noqa: BLE001
        logger.warning("dark_moon_tool_error", tool=tool_name, error=str(exc))
        return {"error": str(exc)}


def _extract_text(content: list) -> str:
    """Join text content items from an MCP response."""
    parts: list[str] = []
    for item in content or []:
        if hasattr(item, "text"):
            parts.append(item.text)
        elif isinstance(item, dict):
            parts.append(item.get("text", str(item)))
        else:
            parts.append(str(item))
    return "\n".join(parts) if parts else ""


def _make_tool_fn(upstream_name: str):
    """Return an async MCP tool function bound to *upstream_name*."""

    async def _call(args: dict, db, auth) -> dict:  # noqa: ARG001 — db/auth unused for subprocess
        return await _invoke_dark_moon_tool(upstream_name, args)

    _call.__name__ = f"dm_{upstream_name}"
    return _call


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

async def _discover_tools() -> list[dict]:
    """Spawn Dark-Moon briefly to retrieve its tool list via MCP protocol."""
    env = {**os.environ, **_DARK_MOON_ENV_OVERRIDES}
    server_params = StdioServerParameters(
        command=DARK_MOON_PYTHON,
        args=["src/server.py"],
        cwd=str(DARK_MOON_PATH),
        env=env,
    )

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await asyncio.wait_for(session.initialize(), timeout=30)
                result = await asyncio.wait_for(session.list_tools(), timeout=15)
                return [
                    {
                        "name": t.name,
                        "description": t.description or "",
                        "inputSchema": t.inputSchema.model_dump()
                        if hasattr(t.inputSchema, "model_dump")
                        else (t.inputSchema if isinstance(t.inputSchema, dict) else {}),
                    }
                    for t in result.tools
                ]
    except Exception as exc:  # noqa: BLE001
        logger.warning("dark_moon_discovery_failed", error=str(exc), path=str(DARK_MOON_PATH))
        return _FALLBACK_TOOLS


# Fallback tool list derived from reading upstream source at integration time.
# Used when the subprocess cannot be spawned (e.g. Docker not running, path missing).
_FALLBACK_TOOLS: list[dict] = [
    {
        "name": "get_session",
        "description": "Return the current MCP session ID generated at server startup.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "health_check",
        "description": (
            "Perform a comprehensive health check of the Darkmoon toolbox: "
            "container status, essential tools availability, disk usage."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "check_tool",
        "description": "Check whether a specific tool is available inside the Darkmoon container.",
        "inputSchema": {
            "type": "object",
            "required": ["tool_name"],
            "properties": {"tool_name": {"type": "string", "description": "Tool name to check"}},
        },
    },
    {
        "name": "diagnose",
        "description": "Run full diagnostics on the Darkmoon environment.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "execute_command",
        "description": (
            "Execute a whitelisted security command inside the Darkmoon Docker container."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["command"],
            "properties": {
                "command": {"type": "string", "description": "Command to execute"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 60)"},
                "workdir": {"type": "string", "description": "Working directory"},
                "session_id": {"type": "string", "description": "Session ID for output isolation"},
            },
        },
    },
    {
        "name": "list_allowed_tools",
        "description": "List all tools available in the Darkmoon container (30+ security tools).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "list_workflows",
        "description": "Discover all pre-built security workflows (port scan, subdomain discovery, etc.).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "run_workflow",
        "description": (
            "Execute a named security workflow (e.g. port_scan, subdomain_discovery, "
            "vulnerability_scan, ad_enumeration, kubernetes_audit, web_crawler)."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["workflow", "method"],
            "properties": {
                "workflow": {"type": "string", "description": "Workflow name"},
                "method": {"type": "string", "description": "Method/action within the workflow"},
                "params": {"type": "object", "description": "Workflow-specific parameters"},
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------

def register_dark_moon_tools() -> None:
    """Discover Dark-Moon tools and register them (``dm_*``) in the MCP registry.

    Called once at startup when ``DARK_MOON_ENABLED=true``.  Uses ``asyncio.run``
    to perform async discovery; this is safe because module imports happen before
    the uvicorn event loop starts.  Falls back to a hardcoded tool list if the
    subprocess cannot be spawned.
    """
    if not DARK_MOON_ENABLED:
        logger.debug("dark_moon_bridge_disabled", reason="DARK_MOON_ENABLED not set")
        return

    logger.info("dark_moon_bridge_starting", path=str(DARK_MOON_PATH))

    # Attempt dynamic discovery; fall back gracefully.
    try:
        tools = asyncio.run(_discover_tools())
    except RuntimeError:
        # Event loop already running (e.g. in tests with pytest-asyncio).
        logger.info("dark_moon_discovery_skipped", reason="event_loop_already_running")
        tools = _FALLBACK_TOOLS

    _register_tools(tools)


def _register_tools(tools: list[dict]) -> None:
    from app.mcp.registry import register_tool

    for tool_def in tools:
        upstream_name = tool_def["name"]
        dm_name = f"dm_{upstream_name}"
        schema = tool_def.get("inputSchema") or {"type": "object", "properties": {}}
        description = f"[Dark-Moon] {tool_def.get('description') or upstream_name}"

        register_tool(
            name=dm_name,
            fn=_make_tool_fn(upstream_name),
            schema=schema,
            description=description,
            scope="write",
        )
        registered_dm_tools.append(dm_name)
        logger.debug("dark_moon_tool_registered", name=dm_name)

    logger.info("dark_moon_tools_registered", count=len(tools), tools=registered_dm_tools)
