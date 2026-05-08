"""MCP tool registry."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any


@dataclass
class McpTool:
    name: str
    fn: Callable[..., Awaitable[Any]]
    schema: dict  # JSON Schema for parameters
    description: str
    scope: str = "read"  # "read" or "write"


_registry: dict[str, McpTool] = {}


def register_tool(
    name: str,
    fn: Callable[..., Awaitable[Any]],
    schema: dict,
    description: str,
    scope: str = "read",
) -> None:
    _registry[name] = McpTool(name=name, fn=fn, schema=schema, description=description, scope=scope)


def get_tool(name: str) -> McpTool | None:
    return _registry.get(name)


def list_tools() -> list[McpTool]:
    return list(_registry.values())
