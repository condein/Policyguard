"""read_file — sandboxed file reader."""

from __future__ import annotations

from pathlib import Path

from app.config import Settings
from app.gateway import provenance, rules

DESCRIPTION = "Read a text or PDF file from workspace/user_files (read-only sandbox)."
SCHEMA = '{"path": "relative/path/inside/workspace/user_files"}'

MAX_CHARS = 8000


def _extract(path: Path) -> tuple[str, str]:
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        try:
            from pypdf import PdfReader

            reader = PdfReader(str(path))
            text = "\n".join((page.extract_text() or "") for page in reader.pages)
            if text.strip():
                return text, "pypdf"
        except Exception:
            pass
        sidecar = path.with_suffix(".txt")
        if sidecar.exists():
            return sidecar.read_text(encoding="utf-8", errors="replace"), "sidecar-txt"
        return "", "empty"
    return path.read_text(encoding="utf-8", errors="replace"), "text"


def run(arguments: dict, settings: Settings, dry_run: bool = False) -> dict:
    raw = str(arguments.get("path", ""))
    info = rules.inspect_path(settings.workspace, raw)
    if not info["ok"]:
        return {"ok": False, "error": info["reason"], "code": info["code"], "provenance": "untrusted"}

    target = (settings.workspace / info["normalized"]).resolve()
    if not target.exists():
        return {"ok": False, "error": f"File not found: {info['normalized']}", "code": "not_found"}
    if target.is_dir():
        return {"ok": False, "error": f"'{info['normalized']}' is a directory", "code": "directory"}

    text, extractor = _extract(target)
    report = provenance.scan_text(text)
    truncated = len(text) > MAX_CHARS

    return {
        "ok": True,
        "path": info["normalized"],
        "content": text[:MAX_CHARS],
        "truncated": truncated,
        "extractor": extractor,
        "chars": len(text),
        "provenance": "untrusted",
        "injection_flags": report.as_dict()["flags"],
        "injection_score": report.score,
    }
