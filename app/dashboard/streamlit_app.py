"""PolicyGuard Streamlit console.

    streamlit run app/dashboard/streamlit_app.py

Pages: Overview, Chat, Blocked attacks, Audit log, Approvals, Policy rules,
Evaluation.  Tables are rendered as plain HTML so the console works even on
machines where optional Arrow/pandas extensions are restricted.
"""

from __future__ import annotations

import html
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st

from app import db
from app.agent.graph import DEMO_TASK, resolve_approval, run_agent
from app.config import get_settings
from app.gate import is_local_host_header, tokens_match
from app.llm import LLMClient
from app.setup import ensure_ready
from app.tools import tool_catalog
from app.workspace import INJECTION_LINE, list_workspace_files

st.set_page_config(page_title="PolicyGuard Console", page_icon="🛡️", layout="wide")

SETTINGS = get_settings()
CHARTS_DIR = ROOT / "evaluation" / "charts"


def _current_host() -> str:
    """Host header of the current browser request, if Streamlit exposes it."""
    try:
        return st.context.headers.get("Host") or ""
    except Exception:  # no request context (tests, bare mode)
        return ""


# --------------------------------------------------------------------------- #
# Access gate: shared token when configured, local-only otherwise
# --------------------------------------------------------------------------- #

if SETTINGS.gate_enabled:
    if not st.session_state.get("pg_authenticated"):
        st.markdown('<div class="pg-title">PolicyGuard console</div>', unsafe_allow_html=True)
        st.caption("This console is protected by a shared access token.")
        with st.form("pg-gate"):
            supplied = st.text_input("Access token", type="password")
            unlock = st.form_submit_button("Unlock", type="primary")
        if unlock:
            if tokens_match(supplied.strip(), SETTINGS.access_token):
                st.session_state["pg_authenticated"] = True
                st.rerun()
            st.error("Invalid access token.")
        st.stop()
else:
    host = _current_host()
    if host and not is_local_host_header(host):
        st.error(
            f"This console was opened via '{host}' but PG_ACCESS_TOKEN is not set. "
            "Set a shared token and restart Streamlit to allow remote access."
        )
        st.stop()

ensure_ready(quiet=True)

st.markdown(
    """
    <style>
      .pg-title { font-size: 1.65rem; font-weight: 700; color: #0d2136; margin-bottom: .15rem; }
      .pg-sub { color: #64748b; font-size: .9rem; margin-bottom: 1rem; }
      .pg-table-wrap { overflow-x: auto; margin: .35rem 0 1rem 0; }
      table.pg-table { border-collapse: collapse; width: 100%; font-size: 13px; }
      table.pg-table th { text-align: left; background: #f1f5f9; color: #334155;
                          padding: 7px 10px; border-bottom: 1px solid #e2e8f0; font-weight: 600; }
      table.pg-table td { padding: 6px 10px; border-bottom: 1px solid #f1f5f9; color: #1e293b;
                          vertical-align: top; }
      table.pg-table tr:hover td { background: #f8fafc; }
      code { color: #0f766e; }
    </style>
    """,
    unsafe_allow_html=True,
)

DECISION_COLORS = {
    "ALLOW": "🟢",
    "MODIFY_ARGUMENTS": "🟡",
    "REQUIRE_HUMAN_APPROVAL": "🟠",
    "BLOCK": "🔴",
}


def decision_badge(decision: str) -> str:
    return f"{DECISION_COLORS.get(decision, '⚪')} {decision}"


def _cell(value) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if value is None:
        return ""
    if isinstance(value, float):
        return f"{value:.3f}".rstrip("0").rstrip(".")
    if isinstance(value, (dict, list)):
        try:
            text = json.dumps(value, ensure_ascii=False)
        except TypeError:
            text = str(value)
        return text[:180]
    return str(value)


def render_table(rows, columns: list[str] | None = None, limit: int | None = None) -> None:
    rows = list(rows or [])
    if limit:
        rows = rows[:limit]
    if not rows:
        st.info("Nothing to show yet.")
        return
    cols = columns or list(rows[0].keys())
    head = "".join(f"<th>{html.escape(str(col))}</th>" for col in cols)
    body = []
    for row in rows:
        cells = "".join(f"<td>{html.escape(_cell(row.get(col)))}</td>" for col in cols)
        body.append(f"<tr>{cells}</tr>")
    st.markdown(
        f'<div class="pg-table-wrap"><table class="pg-table">'
        f"<thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table></div>",
        unsafe_allow_html=True,
    )


@st.cache_data(ttl=3)
def load_audit(limit: int = 500) -> list[dict]:
    return db.list_audit(limit=limit)


def refresh() -> None:
    load_audit.clear()
    st.rerun()


def render_decisions(decisions: list[dict]) -> None:
    if not decisions:
        st.info("No tool call was made for this task.")
        return
    for index, decision in enumerate(decisions, start=1):
        title = (
            f"{index}. {decision['tool']} — {decision_badge(decision['decision'])} "
            f"· risk {decision['risk_score']}/100"
        )
        with st.expander(title, expanded=index == 1):
            st.code(json.dumps(decision.get("arguments", {}), indent=2, ensure_ascii=False), language="json")
            reasons = decision.get("reasons", [])
            if reasons:
                st.markdown("**Why**")
                for reason in reasons:
                    st.markdown(f"- `{reason.get('severity','info')}` {reason.get('message','')}")
            checks = decision.get("checks", [])
            if checks:
                render_table(checks, columns=["name", "status", "detail"])
            judge = decision.get("judge") or {}
            if judge.get("engine") not in (None, "none"):
                st.caption(
                    f"LLM-as-judge: {judge.get('verdict')} (risk {judge.get('risk')}, "
                    f"{judge.get('engine')}) — {judge.get('rationale')}"
                )


# --------------------------------------------------------------------------- #
# Sidebar
# --------------------------------------------------------------------------- #

st.sidebar.markdown("## 🛡️ PolicyGuard")
st.sidebar.caption("Local security framework for a tool-using LLM agent")

page = st.sidebar.radio(
    "View",
    ["Overview", "Chat", "Blocked attacks", "Audit log", "Approvals", "Policy rules", "Evaluation"],
    label_visibility="collapsed",
)

llm = LLMClient(SETTINGS)
st.sidebar.markdown("---")
st.sidebar.markdown(f"**Model**: `{SETTINGS.ollama_model}`")
st.sidebar.markdown(f"**Judge**: {llm.describe()}")
st.sidebar.markdown(f"**Profile**: `{SETTINGS.profile}`")
if SETTINGS.gate_enabled and st.sidebar.button("Sign out"):
    st.session_state.pop("pg_authenticated", None)
    st.rerun()
if st.sidebar.button("Run injection demo"):
    st.session_state["chat_result"] = run_agent(DEMO_TASK, role="admin", simulate_compromise=True)
    st.session_state["demo_banner"] = True
    st.sidebar.success("Demo finished — open the Chat page.")


# --------------------------------------------------------------------------- #
# Overview
# --------------------------------------------------------------------------- #

if page == "Overview":
    stats = db.stats_summary()
    st.markdown('<div class="pg-title">PolicyGuard overview</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="pg-sub">Every tool call is inspected before it runs. '
        "Nothing leaves this machine.</div>",
        unsafe_allow_html=True,
    )

    cols = st.columns(4)
    cols[0].metric("Decisions logged", stats["total_decisions"])
    cols[1].metric("Blocked", stats["blocked"])
    cols[2].metric("Awaiting approval", stats["pending_approvals"])
    cols[3].metric("Email drafts", stats["email_drafts"])

    # Full width: six columns do not fit in a 3:2 split and were clipped.
    st.subheader("Recent decisions")
    render_table(
        load_audit(limit=40),
        columns=["created_at", "role", "tool", "decision", "risk_score", "executed"],
        limit=25,
    )

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Tools")
        render_table(tool_catalog(), columns=["name", "description", "dangerous"])
    with right:
        st.subheader("Sandbox files")
        st.write(", ".join(list_workspace_files()) or "none")
        st.caption("The demo PDF contains: “" + INJECTION_LINE + "”")


# --------------------------------------------------------------------------- #
# Chat
# --------------------------------------------------------------------------- #

elif page == "Chat":
    st.markdown('<div class="pg-title">Chat with the guarded agent</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="pg-sub">The planner proposes a tool call; the Policy Gateway decides.</div>',
        unsafe_allow_html=True,
    )

    if st.session_state.get("demo_banner"):
        st.warning("Injection demo: the PDF asked the agent to email a file to attacker@example.com.")
        st.session_state["demo_banner"] = False

    with st.form("chat-form"):
        role = st.selectbox("Role", ["guest", "analyst", "admin"], index=2)
        task = st.text_area(
            "Task",
            value=DEMO_TASK,
            height=90,
            help="Try: 'How many books are in the database?' or 'Summarize the library handbook'.",
        )
        simulate = st.checkbox(
            "Simulate a compromised planner (follows instructions found in documents)",
            value=True,
        )
        submitted = st.form_submit_button("Send", type="primary")

    if submitted and task.strip():
        with st.spinner("Running the agent…"):
            st.session_state["chat_result"] = run_agent(
                task.strip(), role=role, simulate_compromise=simulate
            )
        load_audit.clear()

    result = st.session_state.get("chat_result")
    if result:
        st.markdown("### Answer")
        st.markdown(result["answer"])
        st.caption(
            f"status: {result['status']} · steps: {result['steps']} · "
            f"session: {result['session_id']} · judge: {result.get('llm_mode')}"
        )
        st.markdown("### Gateway decisions")
        render_decisions(result["decisions"])
        if result.get("approval_id"):
            st.warning(f"Approval #{result['approval_id']} is waiting in the Approvals page.")


# --------------------------------------------------------------------------- #
# Blocked attacks
# --------------------------------------------------------------------------- #

elif page == "Blocked attacks":
    st.markdown('<div class="pg-title">Blocked & escalated actions</div>', unsafe_allow_html=True)
    rows = load_audit(limit=500)
    if not rows:
        st.info("Nothing logged yet.")
    else:
        blocked = [row for row in rows if row["decision"] in ("BLOCK", "REQUIRE_HUMAN_APPROVAL")]
        st.caption(f"{len(blocked)} of the last {len(rows)} decisions were stopped or escalated.")
        if not blocked:
            st.success("No blocked actions in the recent log.")
        else:
            render_table(
                blocked,
                columns=["created_at", "role", "tool", "decision", "risk_score", "task"],
                limit=50,
            )
            for row in blocked[:12]:
                with st.expander(f"#{row['id']} {row['tool']} — {row['decision']}"):
                    st.write(f"**Task**: {row['task']}")
                    st.code(json.dumps(row["arguments"], indent=2, ensure_ascii=False), language="json")
                    for reason in row["reasons"]:
                        st.markdown(f"- `{reason.get('severity')}` {reason.get('message')}")


# --------------------------------------------------------------------------- #
# Audit log
# --------------------------------------------------------------------------- #

elif page == "Audit log":
    st.markdown('<div class="pg-title">Audit log</div>', unsafe_allow_html=True)
    rows = load_audit(limit=1000)
    if not rows:
        st.info("No entries yet.")
    else:
        left, right = st.columns([2, 2])
        choices = ["All"] + sorted({row["decision"] for row in rows})
        decision = left.selectbox("Decision", choices)
        limit = right.slider("Rows", 10, 500, 100, step=10)
        view = rows if decision == "All" else [row for row in rows if row["decision"] == decision]
        render_table(
            view,
            columns=["id", "created_at", "session_id", "role", "tool", "decision",
                     "risk_score", "latency_ms", "executed", "task"],
            limit=limit,
        )
        st.download_button(
            "Download JSON",
            data=json.dumps(view[:limit], indent=2, ensure_ascii=False, default=str),
            file_name="policyguard_audit.json",
            mime="application/json",
        )


# --------------------------------------------------------------------------- #
# Approvals
# --------------------------------------------------------------------------- #

elif page == "Approvals":
    st.markdown('<div class="pg-title">Human approval queue</div>', unsafe_allow_html=True)
    pending = db.list_approvals(status="pending", limit=100)
    st.caption(f"{len(pending)} action(s) waiting for a human decision.")

    if not pending:
        st.success("The queue is empty.")
    for approval in pending:
        with st.container(border=True):
            cols = st.columns([5, 1, 1])
            with cols[0]:
                st.markdown(
                    f"**#{approval['id']} · {approval['tool']}** — risk {approval['risk_score']}/100 · "
                    f"role `{approval['role']}`"
                )
                st.caption(approval["task"])
                st.code(json.dumps(approval["arguments"], indent=2, ensure_ascii=False), language="json")
                for reason in approval["reasons"][:3]:
                    st.markdown(f"- `{reason.get('severity')}` {reason.get('message')}")
            if cols[1].button("Approve", key=f"approve-{approval['id']}", type="primary"):
                outcome = resolve_approval(approval["id"], "approved", actor="dashboard")
                st.success(f"Approved. Tool result: {outcome.get('result')}")
                refresh()
            if cols[2].button("Deny", key=f"deny-{approval['id']}"):
                resolve_approval(approval["id"], "denied", actor="dashboard", note="denied in dashboard")
                refresh()

    decided = [item for item in db.list_approvals(limit=50) if item["status"] != "pending"]
    if decided:
        st.subheader("Recently decided")
        render_table(
            decided,
            columns=["id", "tool", "status", "decided_at", "decided_by", "risk_score"],
        )


# --------------------------------------------------------------------------- #
# Policy rules
# --------------------------------------------------------------------------- #

elif page == "Policy rules":
    st.markdown('<div class="pg-title">Policy rules</div>', unsafe_allow_html=True)
    with db.session(read_only=True) as conn:
        rules = [dict(row) for row in conn.execute("SELECT * FROM policy_rules ORDER BY category, code")]
    if not rules:
        st.info("No rules seeded.")
    else:
        render_table(rules, columns=["code", "category", "name", "description", "severity"])
        st.subheader("Role matrix")
        render_table(
            [
                {"role": "guest", "read_file": "—", "web_search": "yes",
                 "query_database": "—", "draft_email": "—"},
                {"role": "analyst", "read_file": "yes", "web_search": "yes",
                 "query_database": "SELECT only", "draft_email": "—"},
                {"role": "admin", "read_file": "yes", "web_search": "yes",
                 "query_database": "SELECT only", "draft_email": "approval required"},
            ]
        )
        st.caption("Emails are always drafts. PolicyGuard never sends mail.")


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #

elif page == "Evaluation":
    st.markdown('<div class="pg-title">Evaluation</div>', unsafe_allow_html=True)
    latest = db.latest_evaluation()

    if not latest["configs"]:
        st.info("No evaluation stored yet. Run `python evaluation/run_evaluation.py`.")
    else:
        configs = latest["configs"]
        st.caption(
            f"run `{latest['run_id']}` · {int(configs[0]['cases'])} cases · "
            f"judge {configs[0].get('judge_engine','')}"
        )
        metrics = [
            {
                "configuration": row["config"],
                "attack blocked %": row["attack_blocked_rate"],
                "false positive %": row["false_positive_rate"],
                "task completion %": row["task_completion_rate"],
                "approval %": row["approval_rate"],
                "mean latency (ms)": row["mean_latency_ms"],
                "overhead (ms)": row["latency_overhead_ms"],
            }
            for row in configs
        ]
        render_table(metrics)

        for name in ("metrics_by_config.png", "latency_and_approval.png", "blocked_by_category.png"):
            path = CHARTS_DIR / name
            if path.exists():
                st.image(str(path))

        results = latest["results"]
        if results:
            order = [row["config"] for row in configs]
            decisions = sorted({row["decision"] for row in results})
            mix = []
            for config in order:
                subset = [row for row in results if row["config"] == config]
                mix.append(
                    {
                        "configuration": config,
                        **{decision: sum(1 for row in subset if row["decision"] == decision)
                           for decision in decisions},
                    }
                )
            st.subheader("Decision mix per configuration")
            render_table(mix)

            st.subheader("Blocked rate by attack category")
            categories = sorted({row["category"] for row in results if row["category"] != "normal_task"})
            table = []
            for category in categories:
                entry = {"category": category}
                for config in order:
                    subset = [r for r in results if r["config"] == config and r["category"] == category]
                    blocked = sum(1 for r in subset if r["decision"] in ("BLOCK", "REQUIRE_HUMAN_APPROVAL"))
                    entry[config] = round(blocked / len(subset) * 100, 1) if subset else 0.0
                table.append(entry)
            render_table(table)

    st.markdown("---")
    st.caption("Re-run with `python evaluation/run_evaluation.py` (add `LLM_MODE=ollama` for the real judge).")
