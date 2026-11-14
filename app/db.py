"""SQLite persistence layer.

One small module owns every write: audit entries, approval queue, email drafts
and evaluation runs.  Tools and the gateway call these helpers; nothing else
opens a writable connection.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from app.config import get_settings

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "data" / "schema.sql"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _loads(value: Any, fallback: Any) -> Any:
    if value in (None, ""):
        return fallback
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return fallback


def connect(db_path: Path | str | None = None, read_only: bool = False) -> sqlite3.Connection:
    settings = get_settings()
    path = Path(db_path or settings.db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if read_only:
        conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, check_same_thread=False)
    else:
        conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def session(db_path: Path | str | None = None, read_only: bool = False) -> Iterator[sqlite3.Connection]:
    conn = connect(db_path, read_only=read_only)
    try:
        yield conn
        if not read_only:
            conn.commit()
    finally:
        conn.close()


def init_db(reset: bool = False) -> None:
    """Create the schema and seed demo data (idempotent)."""
    from app.seed import seed_all  # local import avoids a cycle

    settings = get_settings()
    settings.ensure_dirs()
    if reset and settings.db_path.exists():
        settings.db_path.unlink()
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    with session() as conn:
        conn.executescript(schema)
    seed_all()


def tables_exist() -> bool:
    settings = get_settings()
    if not settings.db_path.exists():
        return False
    try:
        with session(read_only=True) as conn:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'"
            ).fetchone()
        return row is not None
    except sqlite3.Error:
        return False


# --------------------------------------------------------------------------- #
# Audit log
# --------------------------------------------------------------------------- #

def log_audit(
    *,
    session_id: str = "",
    role: str = "",
    task: str = "",
    tool: str = "",
    arguments: dict | None = None,
    decision: str,
    risk_score: int = 0,
    reasons: Iterable[dict] | None = None,
    trust: dict | None = None,
    judge: dict | None = None,
    latency_ms: float = 0.0,
    executed: bool = False,
    result_preview: str = "",
    profile: str = "full",
) -> int:
    with session() as conn:
        cur = conn.execute(
            """
            INSERT INTO audit_log
                (created_at, session_id, role, task, tool, arguments, decision,
                 risk_score, reasons, trust, judge, latency_ms, executed,
                 result_preview, profile)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now(),
                session_id,
                role,
                task,
                tool,
                _json(arguments or {}),
                decision,
                int(risk_score),
                _json(list(reasons or [])),
                _json(trust or {}),
                _json(judge or {}),
                float(latency_ms),
                1 if executed else 0,
                (result_preview or "")[:800],
                profile,
            ),
        )
        return int(cur.lastrowid)


def list_audit(limit: int = 100, decision: str | None = None, session_id: str | None = None) -> list[dict]:
    clauses, params = [], []
    if decision:
        clauses.append("decision = ?")
        params.append(decision)
    if session_id:
        clauses.append("session_id = ?")
        params.append(session_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(int(limit))
    with session(read_only=True) as conn:
        rows = conn.execute(
            f"SELECT * FROM audit_log {where} ORDER BY id DESC LIMIT ?", params
        ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        item["arguments"] = _loads(item.get("arguments"), {})
        item["reasons"] = _loads(item.get("reasons"), [])
        item["trust"] = _loads(item.get("trust"), {})
        item["judge"] = _loads(item.get("judge"), {})
        item["executed"] = bool(item.get("executed"))
        out.append(item)
    return out


def update_audit_execution(audit_id: int, *, executed: bool, result_preview: str = "") -> None:
    """Mark an audit row as executed once the agent actually ran the tool."""
    try:
        with session() as conn:
            conn.execute(
                "UPDATE audit_log SET executed = ?, result_preview = ? WHERE id = ?",
                (1 if executed else 0, (result_preview or "")[:800], int(audit_id)),
            )
    except sqlite3.Error:
        pass


# --------------------------------------------------------------------------- #
# Approvals
# --------------------------------------------------------------------------- #

def create_approval(
    *,
    session_id: str = "",
    role: str = "",
    task: str = "",
    tool: str = "",
    arguments: dict | None = None,
    risk_score: int = 0,
    reasons: Iterable[dict] | None = None,
) -> int:
    with session() as conn:
        cur = conn.execute(
            """
            INSERT INTO approvals
                (created_at, session_id, role, task, tool, arguments, risk_score, reasons, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
            """,
            (utc_now(), session_id, role, task, tool, _json(arguments or {}), int(risk_score), _json(list(reasons or []))),
        )
        return int(cur.lastrowid)


def list_approvals(status: str | None = None, limit: int = 100) -> list[dict]:
    params: list[Any] = []
    where = ""
    if status:
        where = "WHERE status = ?"
        params.append(status)
    params.append(int(limit))
    with session(read_only=True) as conn:
        rows = conn.execute(f"SELECT * FROM approvals {where} ORDER BY id DESC LIMIT ?", params).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["arguments"] = _loads(item.get("arguments"), {})
        item["reasons"] = _loads(item.get("reasons"), [])
        items.append(item)
    return items


def get_approval(approval_id: int) -> dict | None:
    with session(read_only=True) as conn:
        row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
    if row is None:
        return None
    item = dict(row)
    item["arguments"] = _loads(item.get("arguments"), {})
    item["reasons"] = _loads(item.get("reasons"), [])
    return item


def decide_approval(approval_id: int, decision: str, actor: str = "human", note: str = "") -> dict | None:
    if decision not in ("approved", "denied"):
        raise ValueError("decision must be 'approved' or 'denied'")
    with session() as conn:
        conn.execute(
            "UPDATE approvals SET status = ?, decided_at = ?, decided_by = ?, note = ? WHERE id = ?",
            (decision, utc_now(), actor, note, approval_id),
        )
    return get_approval(approval_id)


# --------------------------------------------------------------------------- #
# Drafts and stats
# --------------------------------------------------------------------------- #

def create_draft(to: str, subject: str, body: str) -> int:
    with session() as conn:
        cur = conn.execute(
            "INSERT INTO email_drafts (created_at, to_addr, subject, body, status) VALUES (?, ?, ?, ?, 'draft')",
            (utc_now(), to, subject, body),
        )
        return int(cur.lastrowid)


def list_drafts(limit: int = 50) -> list[dict]:
    with session(read_only=True) as conn:
        rows = conn.execute("SELECT * FROM email_drafts ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
    return [dict(row) for row in rows]


def stats_summary() -> dict:
    with session(read_only=True) as conn:
        def scalar(sql: str, params: tuple = ()) -> int:
            row = conn.execute(sql, params).fetchone()
            return int(row[0] or 0) if row else 0

        total = scalar("SELECT COUNT(*) FROM audit_log")
        blocked = scalar("SELECT COUNT(*) FROM audit_log WHERE decision = 'BLOCK'")
        approval_required = scalar("SELECT COUNT(*) FROM audit_log WHERE decision = 'REQUIRE_HUMAN_APPROVAL'")
        allowed = scalar("SELECT COUNT(*) FROM audit_log WHERE decision IN ('ALLOW','MODIFY_ARGUMENTS')")
        pending = scalar("SELECT COUNT(*) FROM approvals WHERE status = 'pending'")
        drafts = scalar("SELECT COUNT(*) FROM email_drafts")
    rate = round(blocked / total * 100, 1) if total else 0.0
    return {
        "total_decisions": total,
        "allowed": allowed,
        "blocked": blocked,
        "approval_required": approval_required,
        "block_rate_pct": rate,
        "pending_approvals": pending,
        "email_drafts": drafts,
    }


# --------------------------------------------------------------------------- #
# Evaluation persistence
# --------------------------------------------------------------------------- #

def save_evaluation(run_id: str, metrics_rows: list[dict], per_case: list[dict], judge_engine: str = "") -> None:
    created = utc_now()
    with session() as conn:
        for row in metrics_rows:
            conn.execute(
                """
                INSERT OR REPLACE INTO evaluation_runs
                    (run_id, config, created_at, cases, attack_blocked_rate, false_positive_rate,
                     task_completion_rate, approval_rate, mean_latency_ms, latency_overhead_ms,
                     judge_engine, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    row["config"],
                    created,
                    row["cases"],
                    row["attack_blocked_rate"],
                    row["false_positive_rate"],
                    row["task_completion_rate"],
                    row["approval_rate"],
                    row["mean_latency_ms"],
                    row["latency_overhead_ms"],
                    judge_engine,
                    row.get("notes", ""),
                ),
            )
        conn.executemany(
            """
            INSERT INTO evaluation_results
                (run_id, case_id, category, config, decision, executed, risk_score, latency_ms, expected_decision)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    run_id,
                    item["case_id"],
                    item["category"],
                    item["config"],
                    item["decision"],
                    1 if item.get("executed") else 0,
                    int(item.get("risk_score") or 0),
                    float(item.get("latency_ms") or 0.0),
                    item.get("expected_decision", ""),
                )
                for item in per_case
            ],
        )


def latest_evaluation() -> dict:
    with session(read_only=True) as conn:
        run = conn.execute("SELECT run_id FROM evaluation_runs ORDER BY created_at DESC, rowid DESC LIMIT 1").fetchone()
        if run is None:
            return {"run_id": None, "configs": [], "results": []}
        run_id = run["run_id"]
        configs = [
            dict(r)
            for r in conn.execute(
                """SELECT * FROM evaluation_runs WHERE run_id = ?
                   ORDER BY CASE config WHEN 'baseline' THEN 0 WHEN 'rules' THEN 1
                                        WHEN 'full' THEN 2 ELSE 3 END""",
                (run_id,),
            ).fetchall()
        ]
        results = [dict(r) for r in conn.execute("SELECT * FROM evaluation_results WHERE run_id = ?", (run_id,)).fetchall()]
    return {"run_id": run_id, "configs": configs, "results": results}
