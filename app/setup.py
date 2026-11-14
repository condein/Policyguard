"""One-command bootstrap: schema + seed + demo files.

Run ``python -m app.setup`` (optionally ``--reset``) before anything else.
"""

from __future__ import annotations

import sys

from app import db
from app.config import get_settings
from app.workspace import ensure_workspace_files, list_workspace_files


def ensure_ready(reset: bool = False, quiet: bool = False) -> dict:
    settings = get_settings()
    settings.ensure_dirs()
    if reset or not db.tables_exist():
        db.init_db(reset=reset)
    else:
        db.init_db(reset=False)  # idempotent: adds any missing seed rows
    files = ensure_workspace_files(settings)
    info = {
        "db_path": str(settings.db_path),
        "workspace": str(settings.workspace),
        "created_files": sorted(files),
        "files": list_workspace_files(settings),
        "llm_mode": settings.llm_mode,
        "profile": settings.profile,
    }
    if not quiet:
        print(f"Database : {info['db_path']}")
        print(f"Workspace: {info['workspace']}")
        print(f"LLM mode : {settings.llm_mode} (model {settings.ollama_model})")
        print("Files    : " + ", ".join(info["files"]))
        print("Seed     : users, books, students, loans, documents, 16 policy rules")
    return info


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    reset = "--reset" in args
    ensure_ready(reset=reset)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
