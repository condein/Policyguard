"""FastAPI service for PolicyGuard.

    uvicorn app.api.main:app --reload --port 8000

Routes live on a router so :func:`create_app` can build an isolated instance
with explicit settings; the tests use that instead of mutating the environment.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app import db
from app.agent.graph import DEMO_TASK, resolve_approval, run_agent
from app.config import Settings, get_settings
from app.gate import TOKEN_HEADER, AccessGateMiddleware
from app.llm import LLMClient
from app.setup import ensure_ready
from app.tools import tool_catalog
from app.workspace import ensure_workspace_files


@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_ready(quiet=True)
    yield


router = APIRouter()


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    role: str = "admin"
    session_id: str | None = None
    simulate_compromise: bool = False


class ApprovalDecision(BaseModel):
    decision: str = Field(pattern="^(approve|deny|approved|denied)$")
    actor: str = "reviewer"
    note: str = ""


@router.get("/health")
def health(request: Request) -> dict:
    settings: Settings = request.app.state.settings
    llm = LLMClient(settings)
    return {
        "status": "ok",
        "database": str(settings.db_path),
        "workspace": str(settings.workspace),
        "llm_mode": settings.llm_mode,
        "llm": llm.describe(),
        "profile": settings.profile,
    }


@router.get("/tools")
def tools() -> list[dict]:
    return tool_catalog()


@router.post("/chat")
def chat(request: ChatRequest) -> dict:
    ensure_ready(quiet=True)
    role = request.role.lower()
    if role not in ("guest", "analyst", "admin"):
        raise HTTPException(status_code=400, detail="role must be guest, analyst or admin")
    return run_agent(
        request.message,
        role=role,
        session_id=request.session_id,
        simulate_compromise=request.simulate_compromise,
    )


@router.post("/demo/injection")
def demo_injection() -> dict:
    ensure_ready(quiet=True)
    ensure_workspace_files()
    return run_agent(DEMO_TASK, role="admin", simulate_compromise=True)


@router.get("/audit")
def audit(limit: int = Query(100, ge=1, le=1000), decision: str | None = None) -> list[dict]:
    return db.list_audit(limit=limit, decision=decision)


@router.get("/audit/blocked")
def blocked(limit: int = Query(100, ge=1, le=1000)) -> list[dict]:
    rows = db.list_audit(limit=limit * 2)
    return [row for row in rows if row["decision"] in ("BLOCK", "REQUIRE_HUMAN_APPROVAL")][:limit]


@router.get("/approvals")
def approvals(status: str | None = Query(None), limit: int = Query(100, ge=1, le=500)) -> list[dict]:
    return db.list_approvals(status=status, limit=limit)


@router.post("/approvals/{approval_id}/decide")
def decide(approval_id: int, body: ApprovalDecision) -> dict:
    decision = "approved" if body.decision.startswith("approv") else "denied"
    result = resolve_approval(approval_id, decision, actor=body.actor, note=body.note)
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail=result.get("error", "approval not found"))
    return result


@router.get("/policy/rules")
def policy_rules() -> list[dict]:
    with db.session(read_only=True) as conn:
        rows = conn.execute("SELECT * FROM policy_rules ORDER BY code").fetchall()
    return [dict(row) for row in rows]


@router.get("/stats/summary")
def stats() -> dict:
    return db.stats_summary()


@router.get("/evaluation/latest")
def evaluation() -> dict:
    return db.latest_evaluation()


@router.get("/drafts")
def drafts(limit: int = Query(20, ge=1, le=200)) -> list[dict]:
    return db.list_drafts(limit=limit)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the service.

    ``settings`` is injected so tests can pin the token and CORS allowlist
    without touching the environment or reloading modules.
    """
    settings = settings or get_settings()
    service = FastAPI(
        title="PolicyGuard",
        description="A local policy gateway that guards an LLM agent's tool calls.",
        version="1.0.0",
        lifespan=lifespan,
    )
    service.state.settings = settings
    service.add_middleware(AccessGateMiddleware, settings=settings)
    # Added after the gate so CORS wraps it and 401/403 replies keep their headers.
    service.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.allowed_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", TOKEN_HEADER],
    )
    service.include_router(router)
    return service


app = create_app()
