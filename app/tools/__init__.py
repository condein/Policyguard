"""The four mock tools.

Each tool re-validates its own input (defence in depth) so that even a bug in
the gateway cannot escape the sandbox.  None of them touches the network or
sends real email.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from app.config import Settings, get_settings
from app.tools import draft_email, query_database, read_file, web_search

TOOL_SPECS: dict[str, dict] = {
    "read_file": {
        "description": read_file.DESCRIPTION,
        "schema": read_file.SCHEMA,
        "fn": read_file.run,
        "dangerous": False,
    },
    "web_search": {
        "description": web_search.DESCRIPTION,
        "schema": web_search.SCHEMA,
        "fn": web_search.run,
        "dangerous": False,
    },
    "query_database": {
        "description": query_database.DESCRIPTION,
        "schema": query_database.SCHEMA,
        "fn": query_database.run,
        "dangerous": False,
    },
    "draft_email": {
        "description": draft_email.DESCRIPTION,
        "schema": draft_email.SCHEMA,
        "fn": draft_email.run,
        "dangerous": True,
    },
}

TOOL_NAMES = tuple(TOOL_SPECS)


def tool_catalog() -> list[dict]:
    return [
        {
            "name": name,
            "description": spec["description"],
            "schema": spec["schema"],
            "dangerous": spec["dangerous"],
        }
        for name, spec in TOOL_SPECS.items()
    ]


def execute_tool(
    name: str,
    arguments: dict,
    settings: Settings | None = None,
    dry_run: bool = False,
) -> dict:
    """Execute a tool.  ``dry_run`` validates side effects without writing."""
    settings = settings or get_settings()
    spec = TOOL_SPECS.get(str(name or "").strip().lower())
    if spec is None:
        return {"ok": False, "error": f"unknown tool '{name}'"}
    fn: Callable = spec["fn"]
    try:
        return fn(dict(arguments or {}), settings, dry_run=dry_run)
    except Exception as exc:  # pragma: no cover - defensive
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
