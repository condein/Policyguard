"""draft_email — writes a draft row only. It can never send email."""

from __future__ import annotations

from app.config import Settings
from app.db import create_draft
from app.gateway import rules

DESCRIPTION = "Create an email draft in the local database. Never sends email."
SCHEMA = '{"to": "person@college.edu", "subject": "...", "body": "..."}'


def run(arguments: dict, settings: Settings, dry_run: bool = False) -> dict:
    to = str(arguments.get("to", "")).strip()
    subject = str(arguments.get("subject", "")).strip()
    body = str(arguments.get("body", ""))

    info = rules.inspect_email(to, settings)
    if not info["ok"]:
        return {"ok": False, "error": info["reason"], "code": info["code"]}
    if not subject:
        return {"ok": False, "error": "subject is empty", "code": "empty_subject"}
    if not body.strip():
        return {"ok": False, "error": "body is empty", "code": "empty_body"}

    if dry_run:
        return {
            "ok": True,
            "draft_id": 0,
            "to": to,
            "subject": subject,
            "status": "dry-run",
            "note": "Draft not persisted (evaluation dry run).",
            "provenance": "trusted",
        }

    draft_id = create_draft(to, subject, body)
    return {
        "ok": True,
        "draft_id": draft_id,
        "to": to,
        "subject": subject,
        "status": "draft",
        "note": "Saved locally as a draft. PolicyGuard never sends email.",
        "provenance": "trusted",
    }
