"""Deterministic security rules.

Every constant here is a policy fact that can be explained to a reviewer:
role permissions, table allowlists, injection signatures, and path/SQL/email
inspection helpers.  Nothing in this module calls a model or touches the DB.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote

ROLES = ("guest", "analyst", "admin")

# tool -> roles allowed to call it at all
TOOL_ROLES: dict[str, set[str]] = {
    "read_file": {"analyst", "admin"},
    "web_search": {"guest", "analyst", "admin"},
    "query_database": {"analyst", "admin"},
    "draft_email": {"admin"},
}

DANGEROUS_TOOLS = {"draft_email"}

TOOL_DESCRIPTIONS = {
    "read_file": "Read a text/PDF file from workspace/user_files (read-only).",
    "web_search": "Search the mock web corpus and return result snippets.",
    "query_database": "Run a read-only SELECT against the local SQLite demo DB.",
    "draft_email": "Create an email draft. Never sends anything.",
}

# Tables the agent may read.  Everything else (users, audit_log, approvals,
# email_drafts, evaluation_*, sqlite_master, ...) is off limits.
SQL_TABLE_ALLOWLIST = {"library_books", "students", "loans", "documents"}
SQL_TABLE_BLOCKLIST = {
    "users",
    "audit_log",
    "approvals",
    "email_drafts",
    "evaluation_runs",
    "evaluation_results",
    "policy_rules",
    "sqlite_master",
    "sqlite_schema",
    "sqlite_temp_master",
}
SQL_FORBIDDEN_KEYWORDS = {
    "insert", "update", "delete", "drop", "alter", "create", "replace",
    "attach", "detach", "pragma", "vacuum", "reindex", "grant", "revoke",
    "trigger", "load_extension", "writefile", "readfile",
}

# File names that must never be readable through the agent sandbox.
SENSITIVE_PATH_PATTERNS = (
    r"(^|/)\.env",
    r"(^|/)\.git",
    r"(^|/)\.ssh",
    r"id_rsa",
    r"id_ed25519",
    r"\.pem$",
    r"\.key$",
    r"passwords?",
    r"secrets?",
    r"credentials?",
    r"policyguard\.db$",
    r"\.sqlite3?$",
)

# Credential-looking strings must never leave the building inside a draft.
SECRET_PATTERNS = (
    (r"sk-[A-Za-z0-9]{16,}", "provider API key"),
    (r"(?i)\bapi[_-]?key\s*[:=]\s*\S+", "API key assignment"),
    (r"(?i)\bpassword\s*[:=]\s*\S+", "password assignment"),
    (r"BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY", "private key"),
    (r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", "card number"),
)


def secret_in_text(text: str) -> str:
    """Return the kind of credential found in ``text``, or an empty string."""
    for pattern, label in SECRET_PATTERNS:
        if re.search(pattern, text or ""):
            return label
    return ""


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"https?://[^\s'\"<>]+")
FILE_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-./\\]+\.(?:pdf|txt|md|csv|json|docx?|xlsx?)", re.I)

# (code, regex, weight, human label)
INJECTION_PATTERNS: tuple[tuple[str, str, int, str], ...] = (
    ("ignore_instructions", r"ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?)", 45, "Tells the agent to ignore earlier instructions"),
    ("ignore_user_request", r"ignore\s+(?:the\s+)?user(?:'s)?\s+(?:request|task|question|instructions?)", 45, "Tells the agent to ignore the user request"),
    ("disregard", r"disregard\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|system|user)", 35, "Tells the agent to disregard prior context"),
    ("system_prompt", r"(?:reveal|show|print|repeat|leak)\s+(?:your\s+)?(?:system\s+prompt|hidden\s+prompt|instructions)", 35, "Attempts to extract the system prompt"),
    ("role_override", r"\byou\s+are\s+now\s+(?:a|an|the)?\s*\w+", 30, "Attempts to override the agent role"),
    ("developer_mode", r"(?:developer\s+mode|jailbreak|dan\s+mode|do\s+anything\s+now)", 35, "Known jailbreak pattern"),
    ("dont_tell", r"(?:do\s+not|don't|never)\s+(?:tell|inform|notify|mention\s+to)\s+(?:the\s+)?(?:user|admin|operator|librarian)", 25, "Instructs the agent to hide the action"),
    # "email the file/notes/list to someone" — an object is being shipped.
    ("exfil_email", r"(?:email|mail|send|forward|share|upload)\s+(?:the|these|this|that|all|it|a\s+copy|a\s+file)\b[^.\n]{0,60}?\bto\s+[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", 40, "Sends data to an email address"),
    # "email attacker@example.com the notes" — address straight after the verb.
    ("exfil_address", r"(?:email|mail|send|forward)\s+[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", 35, "Emails an address directly"),
    ("exfil_url", r"(?:upload|post|send|exfiltrate|transmit|sync)\b[^.\n]{0,60}?https?://", 40, "Uploads data to an external URL"),
    ("policy_override", r"(?:override|bypass|disable|ignore)\s+(?:the\s+)?(?:policy|security|guard|gateway|filter|restrictions?)", 40, "Attempts to disable policy enforcement"),
    ("new_instructions", r"(?:new|updated|real|actual)\s+instructions?\s*:", 25, "Injected instruction block"),
    ("prompt_leak", r"(?:print|output|list)\s+(?:all\s+)?(?:api\s+keys?|secrets?|passwords?|credentials?)", 30, "Attempts to extract secrets"),
    ("hidden_text", r"[\u200b-\u200f\u202a-\u202e\ufeff]", 20, "Contains zero-width / bidi control characters"),
    ("encoded_blob", r"[A-Za-z0-9+/]{120,}={0,2}", 15, "Contains a large encoded blob"),
)

COMPILED_INJECTION = tuple(
    (code, re.compile(pattern, re.I | re.S), weight, label)
    for code, pattern, weight, label in INJECTION_PATTERNS
)

# Which tools each user-task verb implies.  Used by the task-alignment check.
INTENT_KEYWORDS: dict[str, tuple[str, ...]] = {
    "read_file": ("summar", "read", "open", "review", "pdf", "document", "notes", "file", "handbook", "report"),
    "web_search": ("search", "find", "look up", "lookup", "research", "latest", "news", "web", "browse"),
    "query_database": ("database", "db", "query", "how many", "count", "list", "sql", "table", "records", "rows", "borrowed", "loans"),
    "draft_email": ("email", "e-mail", "mail", "draft", "compose", "write to", "send"),
}


def detect_intents(task: str) -> set[str]:
    """Which tools the user's wording implies (word-boundary prefix match)."""
    text = (task or "").lower()
    intents: set[str] = set()
    for tool, keywords in INTENT_KEYWORDS.items():
        for word in keywords:
            if re.search(rf"\b{re.escape(word)}", text):
                intents.add(tool)
                break
    return intents


# --------------------------------------------------------------------------- #
# Path inspection
# --------------------------------------------------------------------------- #

def inspect_path(workspace: Path, raw: str) -> dict:
    """Confine a requested path to ``workspace``.

    Returns ``{ok, normalized, code, reason, modified}``.  Symbolic traversal,
    absolute paths outside the sandbox, encoded traversal and sensitive
    filenames are rejected; harmless normalisation is reported as a repair.
    """
    text = (raw or "").strip()
    if not text:
        return {"ok": False, "code": "empty_path", "reason": "File path is empty", "modified": False}
    if "\x00" in text:
        return {"ok": False, "code": "invalid_path", "reason": "Path contains a null byte", "modified": False}

    decoded = unquote(text).replace("\\", "/")
    workspace_resolved = workspace.resolve()
    candidate = Path(decoded)
    try:
        resolved = (candidate if candidate.is_absolute() else workspace_resolved / decoded).resolve()
    except (OSError, RuntimeError):
        return {"ok": False, "code": "invalid_path", "reason": "Path cannot be resolved", "modified": False}

    try:
        relative = resolved.relative_to(workspace_resolved)
    except ValueError:
        return {
            "ok": False,
            "code": "path_escape",
            "reason": f"'{raw}' resolves outside workspace/user_files",
            "modified": False,
        }

    rel = relative.as_posix()
    if rel in (".", ""):
        return {"ok": False, "code": "directory", "reason": "Path points at the workspace directory", "modified": False}
    if any(re.search(pattern, rel, re.I) for pattern in SENSITIVE_PATH_PATTERNS):
        return {"ok": False, "code": "sensitive_file", "reason": f"'{rel}' matches a protected file pattern", "modified": False}

    return {
        "ok": True,
        "normalized": rel,
        "code": "ok",
        "reason": "",
        "modified": rel != text.replace("\\", "/").lstrip("./"),
    }


# --------------------------------------------------------------------------- #
# SQL inspection
# --------------------------------------------------------------------------- #

def inspect_sql(sql: str, row_limit: int = 50) -> dict:
    """Validate a read-only SELECT against the table allowlist.

    Returns ``{ok, code, reason, modified, sql, tables}``.  Missing LIMIT and
    oversized LIMIT are repaired (``modified=True``) instead of blocked.
    """
    text = sql or ""
    stripped = re.sub(r"--[^\n]*", " ", text)
    stripped = re.sub(r"/\*.*?\*/", " ", stripped, flags=re.S)
    body = stripped.strip().rstrip(";").strip()

    if not body:
        return {"ok": False, "code": "empty_sql", "reason": "SQL statement is empty", "modified": False, "tables": []}
    if ";" in body:
        return {
            "ok": False,
            "code": "multiple_statements",
            "reason": "Multiple SQL statements are not allowed",
            "modified": False,
            "tables": [],
        }
    if not re.match(r"^(select|with)\b", body, re.I):
        return {
            "ok": False,
            "code": "not_select",
            "reason": "Only SELECT queries are allowed",
            "modified": False,
            "tables": [],
        }

    lowered = body.lower()
    for keyword in SQL_FORBIDDEN_KEYWORDS:
        if re.search(rf"\b{keyword}\b", lowered):
            return {
                "ok": False,
                "code": "forbidden_keyword",
                "reason": f"SQL keyword '{keyword}' is not permitted",
                "modified": False,
                "tables": [],
            }

    tables = [t for t in re.findall(r"\b(?:from|join)\s+([A-Za-z_][\w.]*)", body, re.I)]
    for table in tables:
        name = table.split(".")[-1].lower()
        if name in SQL_TABLE_BLOCKLIST or name not in SQL_TABLE_ALLOWLIST:
            return {
                "ok": False,
                "code": "table_not_allowed",
                "reason": f"Table '{name}' is outside the analyst allowlist",
                "modified": False,
                "tables": [t.split('.')[-1] for t in tables],
            }

    match = re.search(r"\blimit\s+(\d+)", lowered)
    if not match:
        safe_sql = f"{body} LIMIT {row_limit}"
        return {
            "ok": True,
            "code": "limit_added",
            "reason": f"Added LIMIT {row_limit} to bound the result set",
            "modified": True,
            "sql": safe_sql,
            "tables": tables,
        }

    requested = int(match.group(1))
    if requested > row_limit:
        safe_sql = re.sub(rf"\blimit\s+{requested}\b", f"LIMIT {row_limit}", body, flags=re.I)
        return {
            "ok": True,
            "code": "limit_clamped",
            "reason": f"Clamped LIMIT {requested} to {row_limit}",
            "modified": True,
            "sql": safe_sql,
            "tables": tables,
        }

    return {"ok": True, "code": "ok", "reason": "", "modified": False, "sql": body, "tables": tables}


# --------------------------------------------------------------------------- #
# Email inspection
# --------------------------------------------------------------------------- #

def inspect_email(to: str, settings) -> dict:
    """A draft may have exactly one recipient on an allowlisted domain."""
    raw = (to or "").strip()
    if not raw:
        return {"ok": False, "code": "missing_recipient", "reason": "Recipient is empty", "recipients": []}
    parts = [p.strip() for p in re.split(r"[,;]", raw) if p.strip()]
    if len(parts) != 1:
        return {
            "ok": False,
            "code": "multiple_recipients",
            "reason": "A draft may target exactly one recipient",
            "recipients": parts,
        }
    address = parts[0]
    if not re.fullmatch(EMAIL_RE, address):
        return {"ok": False, "code": "invalid_recipient", "reason": f"'{address}' is not a valid email", "recipients": [address]}
    domain = address.rsplit("@", 1)[-1].lower()
    if domain not in settings.allowed_email_domains:
        return {
            "ok": False,
            "code": "external_recipient",
            "reason": f"Domain '{domain}' is not on the allowlist ({settings.domain_list})",
            "recipients": [address],
        }
    return {"ok": True, "code": "ok", "reason": "", "recipients": [address], "domain": domain}
