"""Central configuration.

Everything is local and free: no cloud keys, no paid APIs.  Ollama is optional
(`LLM_MODE=mock` runs the whole project without it), and all paths live inside
the project folder.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

try:  # python-dotenv is optional at runtime
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - dotenv is in requirements
    def load_dotenv(*args, **kwargs):  # type: ignore[no-redef]
        return False

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

DEFAULT_DB = ROOT / "data" / "policyguard.db"
DEFAULT_WORKSPACE = ROOT / "workspace" / "user_files"


def _str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _int(name: str, default: int) -> int:
    try:
        return int(_str(name) or default)
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(_str(name) or default)
    except ValueError:
        return default


def _domains() -> tuple[str, ...]:
    raw = _str("ALLOWED_EMAIL_DOMAINS", "college.edu,example.edu")
    parts = [p.strip().lower().lstrip("@") for p in raw.split(",") if p.strip()]
    return tuple(parts) or ("college.edu",)


def _origins() -> tuple[str, ...]:
    """CORS allowlist. Never a wildcard: this project has no public API."""
    raw = _str(
        "PG_ALLOWED_ORIGINS",
        "http://localhost:8501,http://127.0.0.1:8501,"
        "http://localhost:8000,http://127.0.0.1:8000",
    )
    return tuple(p.strip().rstrip("/") for p in raw.split(",") if p.strip())


@dataclass
class Settings:
    """Runtime settings.  All values can be overridden with env vars."""

    root: Path = ROOT
    db_path: Path = DEFAULT_DB
    workspace: Path = DEFAULT_WORKSPACE
    llm_mode: str = "auto"  # auto | ollama | mock
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"
    ollama_timeout: float = 45.0
    allowed_email_domains: tuple[str, ...] = field(default_factory=lambda: ("college.edu", "example.edu"))
    risk_allow_max: int = 39
    risk_approval_min: int = 60
    risk_block_min: int = 85
    max_agent_steps: int = 6
    sql_row_limit: int = 50
    profile: str = "full"  # baseline | rules | full
    access_token: str = ""  # PG_ACCESS_TOKEN: empty means local-only
    allowed_origins: tuple[str, ...] = field(
        default_factory=lambda: (
            "http://localhost:8501",
            "http://127.0.0.1:8501",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        )
    )

    def ensure_dirs(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.workspace.mkdir(parents=True, exist_ok=True)

    @property
    def is_mock_llm(self) -> bool:
        return self.llm_mode.lower() == "mock"

    @property
    def domain_list(self) -> str:
        return ", ".join("@" + d for d in self.allowed_email_domains)

    @property
    def gate_enabled(self) -> bool:
        """True when a shared token protects the services."""
        return bool(self.access_token)


def load_settings() -> Settings:
    db = _str("PG_DB_PATH")
    workspace = _str("PG_WORKSPACE_DIR")
    return Settings(
        db_path=Path(db) if db else DEFAULT_DB,
        workspace=Path(workspace) if workspace else DEFAULT_WORKSPACE,
        llm_mode=_str("LLM_MODE", "auto").lower() or "auto",
        ollama_base_url=_str("OLLAMA_BASE_URL", "http://localhost:11434"),
        ollama_model=_str("OLLAMA_MODEL", "llama3.2"),
        ollama_timeout=_float("OLLAMA_TIMEOUT", 45.0),
        allowed_email_domains=_domains(),
        risk_allow_max=_int("RISK_ALLOW_MAX", 39),
        risk_approval_min=_int("RISK_APPROVAL_MIN", 60),
        risk_block_min=_int("RISK_BLOCK_MIN", 85),
        max_agent_steps=_int("MAX_AGENT_STEPS", 6),
        sql_row_limit=_int("SQL_ROW_LIMIT", 50),
        profile=_str("PG_PROFILE", "full").lower() or "full",
        access_token=_str("PG_ACCESS_TOKEN"),
        allowed_origins=_origins(),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = load_settings()
    settings.ensure_dirs()
    return settings
