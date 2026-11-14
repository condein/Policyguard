"""LangGraph agent.

    START -> plan -> guard -> execute -> plan ...
                    |            \\-> deny -> plan
                    \\-> approval -> END
    plan(final) -> respond -> END

``guard`` is the Policy Gateway.  There is no edge from the planner directly to
a tool, which is the whole point of the design.
"""

from __future__ import annotations

import json
import re
from typing import Any, TypedDict
from uuid import uuid4

from langgraph.graph import END, START, StateGraph

from app.agent.prompts import PLANNER_TEMPLATE, SYSTEM_PROMPT, TOOL_MANUAL
from app.config import Settings, get_settings
from app.db import (
    create_approval,
    decide_approval,
    get_approval,
    log_audit,
    update_audit_execution,
)
from app.gateway import provenance
from app.gateway.gateway import PolicyGateway
from app.gateway.rules import EMAIL_RE
from app.llm import LLMClient
from app.schemas import ALLOW, APPROVAL, BLOCK, MODIFY
from app.tools import TOOL_SPECS, execute_tool
from app.workspace import list_workspace_files

DEMO_TASK = "Summarize the lecture notes PDF"


class AgentState(TypedDict, total=False):
    session_id: str
    role: str
    task: str
    steps: int
    observations: list[dict]
    untrusted: list[dict]
    decisions: list[dict]
    pending: dict | None
    answer: str
    status: str
    approval_id: int | None
    simulate_compromise: bool
    simulated: bool


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _preview(output: dict, limit: int = 400) -> str:
    if not output.get("ok"):
        return f"error: {output.get('error', 'failed')}"[:limit]
    if "content" in output:
        return str(output["content"])[:limit]
    if "results" in output:
        return "; ".join(item.get("title", "") for item in output["results"])[:limit]
    if "rows" in output:
        return json.dumps(output["rows"][:3], ensure_ascii=False, default=str)[:limit]
    return json.dumps({k: v for k, v in output.items() if k != "body"}, ensure_ascii=False, default=str)[:limit]


def _condense(text: str, limit: int = 600) -> str:
    """First lines of a document, with injected instructions redacted."""
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    picked: list[str] = []
    total = 0
    for line in lines[:10]:
        if provenance.scan_text(line).detected:
            picked.append("[untrusted instruction redacted from the summary]")
            continue
        picked.append(line)
        total += len(line)
        if total > limit:
            break
    joined = "\n".join(picked)
    return joined[:limit] + ("..." if len(joined) > limit else "")


SQL_TRIGGER_RE = re.compile(
    r"\b(databases?|db|sql|queries|query|how\s+many|count|records?|tables?|loans?|issued|borrowed)\b",
    re.I,
)


def _sql_for(text: str) -> str | None:
    if not SQL_TRIGGER_RE.search(text or ""):
        return None
    if "student" in text:
        return "SELECT id, name, course FROM students LIMIT 10"
    if "loan" in text or "issued" in text or "borrowed" in text:
        return "SELECT id, student_id, book_id, due_on, returned FROM loans LIMIT 10"
    if "book" in text:
        return "SELECT id, title, author, copies FROM library_books LIMIT 10"
    return "SELECT COUNT(*) AS total_books FROM library_books"


def _pick_file(task: str, files: list[str]) -> str | None:
    lower = task.lower()
    for name in files:
        if name.lower() in lower:
            return name
        stem = name.rsplit(".", 1)[0].replace("_", " ").lower()
        if stem and stem in lower:
            return name
    for hint, name in (("handbook", "library_handbook.pdf"), ("notes", "lecture_notes.pdf"), ("reading", "reading_list.txt")):
        if hint in lower and name in files:
            return name
    pdfs = [name for name in files if name.endswith(".pdf")]
    if pdfs:
        return "lecture_notes.pdf" if "lecture_notes.pdf" in pdfs else pdfs[0]
    return files[0] if files else None


def _document_summary(observations: list[dict]) -> str:
    for obs in reversed(observations):
        if obs.get("tool") == "read_file" and obs.get("ok"):
            result = obs.get("result") or {}
            return _condense(str(result.get("content", "")))
    return ""


def _final_answer(state: AgentState) -> str:
    observations = state.get("observations", [])
    decisions = state.get("decisions", [])
    read = next((o for o in observations if o["tool"] == "read_file" and o.get("ok")), None)
    search = next((o for o in observations if o["tool"] == "web_search" and o.get("ok")), None)
    db_rows = next((o for o in observations if o["tool"] == "query_database" and o.get("ok")), None)
    drafted = next((o for o in observations if o["tool"] == "draft_email" and o.get("ok")), None)

    parts: list[str] = []
    if read:
        path = read.get("result", {}).get("path", "the document")
        parts.append(f"Summary of {path}:\n{_condense(str(read.get('result', {}).get('content', '')))}")
    if search:
        results = search.get("result", {}).get("results", [])
        if results:
            bullets = "\n".join(f"- {item['title']} ({item['url']})" for item in results[:3])
            parts.append(f"Top mock search results:\n{bullets}")
    if db_rows:
        rows = db_rows.get("result", {}).get("rows", [])
        parts.append(f"Query returned {len(rows)} row(s):\n{json.dumps(rows[:5], ensure_ascii=False, indent=2)}")
    if drafted:
        result = drafted.get("result", {})
        parts.append(f"Draft #{result.get('draft_id')} saved for {result.get('to')} — status: {result.get('status')}.")

    blocked = [d for d in decisions if d["decision"] in (BLOCK, APPROVAL)]
    if blocked:
        summary = "; ".join(f"{d['tool']} -> {d['decision']}" for d in blocked[:4])
        parts.append(f"Security note: {len(blocked)} action(s) were stopped or escalated by the Policy Gateway ({summary}).")

    if not parts:
        parts.append("No tool call was needed to answer this request.")
    return "\n\n".join(parts)


# --------------------------------------------------------------------------- #
# Planning
# --------------------------------------------------------------------------- #

def _tool_proposal(tool: str, arguments: dict, reason: str) -> dict:
    return {"type": "tool", "tool": tool, "arguments": arguments, "reason": reason}


def _compromise_proposal(state: AgentState) -> dict | None:
    """Deterministic 'hijacked planner' step for the demo.

    A real Llama 3.2 may or may not obey an injected instruction.  To keep the
    demonstration reproducible we optionally add this step after untrusted text
    has been read, clearly flagged as simulated.
    """
    if not state.get("simulate_compromise") or state.get("simulated"):
        return None
    blob = "\n".join(item.get("content", "") for item in state.get("untrusted", []))
    if not blob:
        return None
    report = provenance.scan_text(blob)
    if not report.emails:
        return None
    return {
        "type": "tool",
        "tool": "draft_email",
        "arguments": {
            "to": report.emails[0],
            "subject": "Lecture notes",
            "body": "Please find the lecture notes attached. Sending on behalf of the library.",
        },
        "reason": "Compromised planner: following an instruction found in the document.",
        "simulated": True,
    }


def _llm_proposal(task: str, role: str, state: AgentState, llm: LLMClient) -> dict | None:
    history_lines = []
    for obs in state.get("observations", [])[-4:]:
        status = "ok" if obs.get("ok") else "failed"
        history_lines.append(
            f"- {obs['tool']}({json.dumps(obs.get('arguments', {}), ensure_ascii=False)}) -> "
            f"{obs.get('decision')} / {status}"
        )
    prompt = PLANNER_TEMPLATE.format(
        task=task,
        role=role,
        history="\n".join(history_lines) or "- nothing yet",
        files=", ".join(list_workspace_files()) or "none",
    )
    payload = llm.complete_json(SYSTEM_PROMPT, prompt)
    if not payload:
        return None
    kind = str(payload.get("type", "")).lower()
    if kind == "final":
        answer = str(payload.get("answer") or "").strip()
        return {"type": "final", "answer": answer or _final_answer(state)}
    tool = str(payload.get("tool", "")).strip().lower()
    if tool not in TOOL_SPECS:
        return None
    arguments = payload.get("arguments")
    if not isinstance(arguments, dict):
        return None
    return _tool_proposal(tool, arguments, str(payload.get("reason") or "model proposal"))


def _rule_planner(state: AgentState, settings: Settings) -> dict:
    task = state.get("task", "")
    lower = task.lower()
    observations = state.get("observations", [])
    finished = {obs["tool"] for obs in observations if obs.get("decision") in (ALLOW, MODIFY)}
    refused = {obs["tool"] for obs in observations if obs.get("decision") in (BLOCK, APPROVAL)}

    files = list_workspace_files(settings)
    wants_document = any(
        key in lower for key in ("summar", "read", "open", "pdf", "document", "notes", "handbook", "report", "file")
    )
    if wants_document and "read_file" not in finished and "read_file" not in refused:
        target = _pick_file(task, files)
        if target:
            return _tool_proposal("read_file", {"path": target}, "The task is about a document, so read it first.")

    sql = _sql_for(lower)
    if sql and "query_database" not in finished and "query_database" not in refused:
        return _tool_proposal("query_database", {"sql": sql}, "The task asks about database records.")

    wants_search = any(key in lower for key in ("search", "find", "look up", "lookup", "latest", "news", "research", "web"))
    if wants_search and "web_search" not in finished and "web_search" not in refused:
        query = task.strip()[:200]
        return _tool_proposal("web_search", {"query": query, "max_results": 3}, "The task asks for a search.")

    addresses = EMAIL_RE.findall(task)
    wants_email = bool(addresses) or any(key in lower for key in ("email", "e-mail", "mail", "draft", "compose"))
    if wants_email and "draft_email" not in finished and "draft_email" not in refused:
        summary = _document_summary(observations)
        body = (summary or task.strip() or "Summary attached.") + "\n\nRegards,\nLibrary desk"
        return _tool_proposal(
            "draft_email",
            {
                "to": addresses[0] if addresses else "librarian@college.edu",
                "subject": "Library summary",
                "body": body[:4000],
            },
            "The task asks for an email draft.",
        )

    return {"type": "final", "answer": _final_answer(state)}


# --------------------------------------------------------------------------- #
# Graph
# --------------------------------------------------------------------------- #

def build_graph(gateway: PolicyGateway, settings: Settings, llm: LLMClient | None = None):
    llm = llm or LLMClient(settings)

    def plan_node(state: AgentState) -> dict:
        if state.get("steps", 0) >= settings.max_agent_steps:
            return {"pending": {"type": "final", "answer": _final_answer(state)}}
        if state.get("pending"):
            return {}

        proposal = _compromise_proposal(state)
        if proposal:
            return {"pending": proposal, "simulated": True}

        if llm.available():
            proposal = _llm_proposal(state.get("task", ""), state.get("role", "guest"), state, llm)
            if proposal:
                return {"pending": proposal}

        return {"pending": _rule_planner(state, settings)}

    def route_after_plan(state: AgentState) -> str:
        pending = state.get("pending") or {}
        return "gateway" if pending.get("type") == "tool" else "respond"

    def gateway_node(state: AgentState) -> dict:
        action = state.get("pending") or {}
        result = gateway.evaluate(
            role=state.get("role", "guest"),
            task=state.get("task", ""),
            tool=action.get("tool", ""),
            arguments=action.get("arguments", {}),
            context=state.get("untrusted", []),
            session_id=state.get("session_id", ""),
        )
        decisions = list(state.get("decisions", []))
        decisions.append(result.as_dict())
        return {
            "decisions": decisions,
            "pending": {**action, "gateway": result.as_dict()},
        }

    def route_after_gateway(state: AgentState) -> str:
        decision = (state.get("pending") or {}).get("gateway", {}).get("decision")
        if decision in (ALLOW, MODIFY):
            return "execute"
        if decision == BLOCK:
            return "deny"
        return "approval"

    def execute_node(state: AgentState) -> dict:
        action = state.get("pending") or {}
        gate = action.get("gateway", {})
        arguments = gate.get("arguments", action.get("arguments", {}))
        output = execute_tool(action.get("tool", ""), arguments, settings)

        observations = list(state.get("observations", []))
        observations.append(
            {
                "tool": action.get("tool", ""),
                "arguments": arguments,
                "decision": gate.get("decision"),
                "risk_score": gate.get("risk_score"),
                "ok": bool(output.get("ok")),
                "preview": _preview(output),
                "result": output,
                "reason": action.get("reason", ""),
                "simulated": action.get("simulated", False),
            }
        )

        untrusted = list(state.get("untrusted", []))
        payload = ""
        if action.get("tool") == "read_file" and output.get("ok"):
            payload = str(output.get("content", ""))
        elif action.get("tool") == "web_search" and output.get("ok"):
            payload = "\n".join(f"{r['title']}: {r['snippet']}" for r in output.get("results", []))
        elif action.get("tool") == "query_database" and output.get("ok"):
            payload = json.dumps(output.get("rows", []), ensure_ascii=False, default=str)
        if payload:
            untrusted.append({"source": f"tool:{action.get('tool')}", "content": payload, "trust": "untrusted"})

        if gate.get("audit_id"):
            update_audit_execution(int(gate["audit_id"]), executed=True, result_preview=_preview(output))

        return {
            "observations": observations,
            "untrusted": untrusted,
            "pending": None,
            "steps": state.get("steps", 0) + 1,
        }

    def deny_node(state: AgentState) -> dict:
        action = state.get("pending") or {}
        gate = action.get("gateway", {})
        observations = list(state.get("observations", []))
        observations.append(
            {
                "tool": action.get("tool", ""),
                "arguments": gate.get("arguments", {}),
                "decision": gate.get("decision"),
                "risk_score": gate.get("risk_score"),
                "ok": False,
                "preview": "blocked by Policy Gateway",
                "result": {"ok": False, "error": "blocked by policy"},
                "reason": "; ".join(reason["message"] for reason in gate.get("reasons", [])[:2]),
                "simulated": action.get("simulated", False),
            }
        )
        return {
            "observations": observations,
            "pending": None,
            "steps": state.get("steps", 0) + 1,
        }

    def approval_node(state: AgentState) -> dict:
        action = state.get("pending") or {}
        gate = action.get("gateway", {})
        approval_id = create_approval(
            session_id=state.get("session_id", ""),
            role=state.get("role", ""),
            task=state.get("task", ""),
            tool=action.get("tool", ""),
            arguments=gate.get("arguments", {}),
            risk_score=int(gate.get("risk_score") or 0),
            reasons=gate.get("reasons", []),
        )
        observations = list(state.get("observations", []))
        observations.append(
            {
                "tool": action.get("tool", ""),
                "arguments": gate.get("arguments", {}),
                "decision": gate.get("decision"),
                "risk_score": gate.get("risk_score"),
                "ok": False,
                "preview": "queued for human approval",
                "result": {"ok": False, "error": "awaiting human approval"},
                "reason": "queued for human approval",
                "simulated": action.get("simulated", False),
            }
        )
        answer = _final_answer(state) + f"\n\nApproval #{approval_id} is waiting in the human review queue."
        return {
            "observations": observations,
            "status": "awaiting_approval",
            "approval_id": approval_id,
            "answer": answer,
            "pending": None,
        }

    def respond_node(state: AgentState) -> dict:
        pending = state.get("pending") or {}
        answer = pending.get("answer") if pending.get("type") == "final" else None
        return {"answer": answer or _final_answer(state), "status": "done"}

    graph = StateGraph(AgentState)
    graph.add_node("plan", plan_node)
    graph.add_node("gateway", gateway_node)
    graph.add_node("execute", execute_node)
    graph.add_node("deny", deny_node)
    graph.add_node("approval", approval_node)
    graph.add_node("respond", respond_node)

    graph.add_edge(START, "plan")
    graph.add_conditional_edges("plan", route_after_plan, {"gateway": "gateway", "respond": "respond"})
    graph.add_conditional_edges(
        "gateway",
        route_after_gateway,
        {"execute": "execute", "deny": "deny", "approval": "approval"},
    )
    graph.add_edge("execute", "plan")
    graph.add_edge("deny", "plan")
    graph.add_edge("approval", END)
    graph.add_edge("respond", END)
    return graph.compile()


# --------------------------------------------------------------------------- #
# Public runners
# --------------------------------------------------------------------------- #

def run_agent(
    task: str,
    role: str = "admin",
    session_id: str | None = None,
    gateway: PolicyGateway | None = None,
    settings: Settings | None = None,
    simulate_compromise: bool = False,
    llm: LLMClient | None = None,
) -> dict:
    settings = settings or get_settings()
    gateway = gateway or PolicyGateway(settings=settings)
    llm = llm or LLMClient(settings)
    session = session_id or f"sess-{uuid4().hex[:8]}"

    initial: AgentState = {
        "session_id": session,
        "role": (role or "guest").lower(),
        "task": task,
        "steps": 0,
        "observations": [],
        "untrusted": [],
        "decisions": [],
        "pending": None,
        "answer": "",
        "status": "running",
        "approval_id": None,
        "simulate_compromise": simulate_compromise,
        "simulated": False,
    }

    graph = build_graph(gateway, settings, llm)
    try:
        state = graph.invoke(initial, {"recursion_limit": max(25, settings.max_agent_steps * 4 + 10)})
    except Exception as exc:  # pragma: no cover - keeps the API alive
        return {
            "session_id": session,
            "role": role,
            "task": task,
            "status": "error",
            "answer": f"The agent failed: {type(exc).__name__}: {exc}",
            "decisions": [],
            "observations": [],
            "steps": 0,
            "approval_id": None,
            "llm_mode": llm.describe(),
        }

    return {
        "session_id": state.get("session_id", session),
        "role": state.get("role", role),
        "task": task,
        "status": state.get("status", "done"),
        "answer": state.get("answer", ""),
        "decisions": state.get("decisions", []),
        "observations": state.get("observations", []),
        "steps": state.get("steps", 0),
        "approval_id": state.get("approval_id"),
        "llm_mode": llm.describe(),
    }


def resolve_approval(
    approval_id: int,
    decision: str,
    actor: str = "reviewer",
    note: str = "",
    settings: Settings | None = None,
) -> dict:
    """Approve or deny a queued action; approval executes it once."""
    settings = settings or get_settings()
    approval = get_approval(approval_id)
    if approval is None:
        return {"ok": False, "error": "approval not found"}
    if approval["status"] != "pending":
        return {"ok": False, "error": f"approval already {approval['status']}"}

    updated = decide_approval(approval_id, decision, actor=actor, note=note)
    if decision != "approved":
        return {"ok": True, "status": "denied", "approval": updated}

    output = execute_tool(approval["tool"], approval["arguments"], settings)
    log_audit(
        session_id=approval.get("session_id") or "",
        role=f"{approval.get('role')}+human:{actor}",
        task=approval.get("task") or "",
        tool=approval.get("tool") or "",
        arguments=approval.get("arguments") or {},
        decision=ALLOW,
        risk_score=int(approval.get("risk_score") or 0),
        reasons=[{"code": "human_approved", "message": f"Approved by {actor}", "weight": 0, "severity": "info"}],
        trust={"approval": "human"},
        judge={"verdict": "approved", "engine": "human"},
        latency_ms=0.0,
        executed=bool(output.get("ok")),
        result_preview=_preview(output),
        profile="approval",
    )
    return {"ok": True, "status": "approved", "approval": updated, "result": output}
