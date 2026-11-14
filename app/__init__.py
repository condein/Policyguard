"""PolicyGuard — a local security framework for LLM agents.

The package is intentionally small and layered:

    config.py        environment driven settings
    db.py            SQLite schema + audit/approval persistence
    gateway/         the Policy Gateway (rules, provenance, judge)
    tools/           the four mock tools
    agent/           LangGraph agent that calls the gateway before tools
    api/             FastAPI service
    dashboard/       Streamlit console
"""

__version__ = "1.0.0"

# Must run before any langchain/langgraph import (see app/compat.py).
from app.compat import ensure_uuid7  # noqa: E402

ensure_uuid7()
