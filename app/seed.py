"""Seed data: library records, demo documents and the policy rule catalogue."""

from __future__ import annotations

from app.config import get_settings
from app.db import session
from app.workspace import ensure_workspace_files

USERS = [
    ("u-001", "Priya Menon", "admin"),
    ("u-002", "Rahul Verma", "analyst"),
    ("u-003", "Sam Fernandes", "guest"),
]

BOOKS = [
    ("B-1001", "Security Engineering", "Ross Anderson", "Security", 3),
    ("B-1002", "The Web Application Hacker's Handbook", "Stuttard & Pinto", "Security", 2),
    ("B-1003", "Introduction to Algorithms", "Cormen et al.", "Computer Science", 5),
    ("B-1004", "Database System Concepts", "Silberschatz", "Computer Science", 4),
    ("B-1005", "Clean Architecture", "Robert C. Martin", "Software", 2),
    ("B-1006", "Designing Data-Intensive Applications", "Martin Kleppmann", "Software", 3),
    ("B-1007", "Artificial Intelligence: A Modern Approach", "Russell & Norvig", "AI", 4),
    ("B-1008", "Deep Learning", "Goodfellow et al.", "AI", 2),
    ("B-1009", "Operating System Concepts", "Silberschatz", "Computer Science", 6),
    ("B-1010", "The Pragmatic Programmer", "Hunt & Thomas", "Software", 3),
]

STUDENTS = [
    ("STU-2026-CS-001", "Aarav Sharma", "B.Tech CSE", "+91 98123 45601", "aarav@college.edu"),
    ("STU-2026-CS-002", "Meera Iyer", "B.Tech CSE", "+91 98123 45602", "meera@college.edu"),
    ("STU-2026-IT-003", "Kabir Nair", "B.Tech IT", "+91 98123 45603", "kabir@college.edu"),
    ("STU-2026-EC-004", "Diya Patel", "B.Tech ECE", "+91 98123 45604", "diya@college.edu"),
    ("STU-2026-CS-005", "Rohan Gupta", "M.Tech CSE", "+91 98123 45605", "rohan@college.edu"),
    ("STU-2026-IT-006", "Ananya Rao", "B.Tech IT", "+91 98123 45606", "ananya@college.edu"),
]

LOANS = [
    ("L-9001", "STU-2026-CS-001", "B-1001", "2026-10-20", "2026-11-03", 0),
    ("L-9002", "STU-2026-CS-002", "B-1003", "2026-10-28", "2026-11-11", 0),
    ("L-9003", "STU-2026-IT-003", "B-1006", "2026-09-30", "2026-10-14", 0),
    ("L-9004", "STU-2026-CS-005", "B-1007", "2026-10-02", "2026-10-16", 1),
    ("L-9005", "STU-2026-EC-004", "B-1004", "2026-10-25", "2026-11-08", 0),
    ("L-9006", "STU-2026-IT-006", "B-1002", "2026-10-10", "2026-10-24", 1),
]

DOCUMENTS = [
    ("doc-001", "lecture_notes.pdf", "CS-402 Lecture 7 — prompt injection", "untrusted",
     "Contains an embedded instruction aimed at the assistant (demo)."),
    ("doc-002", "library_handbook.pdf", "Library handbook (excerpt)", "untrusted",
     "Benign reference document."),
    ("doc-003", "reading_list.txt", "CS-402 reading list", "untrusted", "Benign reading list."),
    ("doc-004", "research_notes.md", "Agent safety notes", "untrusted", "Benign notes."),
]

POLICY_RULES = [
    ("PG-001", "Role-based tool access", "RBAC",
     "guest: web_search only. analyst: read_file, web_search, query_database. admin: all tools.",
     "high"),
    ("PG-002", "Global tool allowlist", "Allowlist",
     "Only read_file, web_search, query_database and draft_email may be invoked.", "high"),
    ("PG-003", "JSON argument schema", "Validation",
     "Every tool call is validated against a Pydantic schema; unknown fields are dropped.",
     "medium"),
    ("PG-004", "File path confinement", "Filesystem",
     "Paths must resolve inside workspace/user_files; traversal and absolute escapes are blocked.",
     "critical"),
    ("PG-005", "Sensitive file protection", "Filesystem",
     "Names matching .env, .git, id_rsa, *.pem, *.key, secrets, credentials or the app DB are blocked.",
     "critical"),
    ("PG-006", "SELECT-only SQL", "Database",
     "Only single SELECT/WITH statements are allowed; DDL/DML keywords are rejected.", "critical"),
    ("PG-007", "SQL table allowlist", "Database",
     "Only library_books, students, loans and documents may be queried.", "high"),
    ("PG-008", "Bounded result sets", "Database",
     "A missing LIMIT is added automatically and oversized limits are clamped.", "low"),
    ("PG-009", "Email domain allowlist", "Email",
     "Drafts may only target recipients on the configured institutional domains.", "high"),
    ("PG-010", "Single visible recipient", "Email",
     "Exactly one recipient; cc/bcc fields are refused so copies cannot be hidden.", "high"),
    ("PG-011", "Injection signature scan", "Injection",
     "Rule-based regexes catch instruction overrides, role hijacks and exfiltration phrasing.",
     "high"),
    ("PG-012", "Provenance labels", "Injection",
     "User text is trusted; PDF, web and tool output are untrusted and can never grant permission.",
     "high"),
    ("PG-013", "Task/action alignment", "Task match",
     "The proposed tool must be implied by the original user task.", "medium"),
    ("PG-014", "LLM-as-judge risk score", "Judge",
     "Llama 3.2 rates 0-100 how likely the call is hijacked or unrelated to the task.", "medium"),
    ("PG-015", "Human approval for dangerous actions", "Approval",
     "Admin email drafts and high-risk calls wait in the approval queue.", "high"),
    ("PG-016", "Exfiltration guard", "Data loss",
     "Arguments copied from untrusted content (addresses, URLs, filenames) block the call.",
     "critical"),
]


def seed_all() -> None:
    settings = get_settings()
    ensure_workspace_files(settings)

    with session() as conn:
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            conn.executemany("INSERT INTO users (id, name, role) VALUES (?, ?, ?)", USERS)
        if conn.execute("SELECT COUNT(*) FROM library_books").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO library_books (id, title, author, category, copies) VALUES (?, ?, ?, ?, ?)",
                BOOKS,
            )
        if conn.execute("SELECT COUNT(*) FROM students").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO students (id, name, course, contact, email) VALUES (?, ?, ?, ?, ?)",
                STUDENTS,
            )
        if conn.execute("SELECT COUNT(*) FROM loans").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO loans (id, student_id, book_id, issued_on, due_on, returned) VALUES (?, ?, ?, ?, ?, ?)",
                LOANS,
            )
        if conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO documents (id, path, title, provenance, notes) VALUES (?, ?, ?, ?, ?)",
                DOCUMENTS,
            )
        if conn.execute("SELECT COUNT(*) FROM policy_rules").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO policy_rules (code, name, category, description, severity, enabled) "
                "VALUES (?, ?, ?, ?, ?, 1)",
                POLICY_RULES,
            )
