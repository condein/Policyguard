"""query_database — read-only SELECT against the local SQLite demo DB."""

from __future__ import annotations

import sqlite3

from app.config import Settings
from app.db import session
from app.gateway import rules

DESCRIPTION = "Run a read-only SELECT on the local SQLite demo database."
SCHEMA = '{"sql": "SELECT ... FROM library_books LIMIT 10"}'


def run(arguments: dict, settings: Settings, dry_run: bool = False) -> dict:
    sql = str(arguments.get("sql", ""))
    info = rules.inspect_sql(sql, settings.sql_row_limit)
    if not info["ok"]:
        return {"ok": False, "error": info["reason"], "code": info["code"]}

    safe_sql = info["sql"]
    try:
        with session(read_only=True) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(safe_sql)
            rows = cursor.fetchmany(settings.sql_row_limit)
        data = [dict(row) for row in rows]
    except sqlite3.Error as exc:
        return {"ok": False, "error": f"SQLite error: {exc}", "code": "sql_error"}
    except Exception as exc:  # pragma: no cover
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "code": "sql_error"}

    return {
        "ok": True,
        "sql": safe_sql,
        "row_count": len(data),
        "rows": data,
        "provenance": "untrusted",
    }
