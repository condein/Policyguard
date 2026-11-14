-- PolicyGuard SQLite schema.  Idempotent: safe to run on every start.

CREATE TABLE IF NOT EXISTS users (
    id      TEXT PRIMARY KEY,
    name    TEXT NOT NULL,
    role    TEXT NOT NULL CHECK (role IN ('guest', 'analyst', 'admin'))
);

CREATE TABLE IF NOT EXISTS library_books (
    id       TEXT PRIMARY KEY,
    title    TEXT NOT NULL,
    author   TEXT NOT NULL,
    category TEXT NOT NULL,
    copies   INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS students (
    id      TEXT PRIMARY KEY,
    name    TEXT NOT NULL,
    course  TEXT NOT NULL,
    contact TEXT,
    email   TEXT
);

CREATE TABLE IF NOT EXISTS loans (
    id         TEXT PRIMARY KEY,
    student_id TEXT NOT NULL REFERENCES students(id),
    book_id    TEXT NOT NULL REFERENCES library_books(id),
    issued_on  TEXT NOT NULL,
    due_on     TEXT NOT NULL,
    returned   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS documents (
    id         TEXT PRIMARY KEY,
    path       TEXT NOT NULL,
    title      TEXT NOT NULL,
    provenance TEXT NOT NULL DEFAULT 'untrusted',
    notes      TEXT
);

CREATE TABLE IF NOT EXISTS policy_rules (
    code        TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    category    TEXT NOT NULL,
    description TEXT NOT NULL,
    severity    TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS audit_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at     TEXT NOT NULL,
    session_id     TEXT,
    role           TEXT,
    task           TEXT,
    tool           TEXT,
    arguments      TEXT,
    decision       TEXT NOT NULL,
    risk_score     INTEGER NOT NULL DEFAULT 0,
    reasons        TEXT,
    trust          TEXT,
    judge          TEXT,
    latency_ms     REAL,
    executed       INTEGER NOT NULL DEFAULT 0,
    result_preview TEXT,
    profile        TEXT NOT NULL DEFAULT 'full'
);

CREATE TABLE IF NOT EXISTS approvals (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,
    session_id  TEXT,
    role        TEXT,
    task        TEXT,
    tool        TEXT,
    arguments   TEXT,
    risk_score  INTEGER NOT NULL DEFAULT 0,
    reasons     TEXT,
    status      TEXT NOT NULL DEFAULT 'pending',
    decided_at  TEXT,
    decided_by  TEXT,
    note        TEXT
);

CREATE TABLE IF NOT EXISTS email_drafts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    to_addr    TEXT NOT NULL,
    subject    TEXT NOT NULL,
    body       TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'draft'
);

CREATE TABLE IF NOT EXISTS evaluation_runs (
    run_id                TEXT NOT NULL,
    config                TEXT NOT NULL,
    created_at            TEXT NOT NULL,
    cases                 INTEGER NOT NULL,
    attack_blocked_rate   REAL,
    false_positive_rate   REAL,
    task_completion_rate  REAL,
    approval_rate         REAL,
    mean_latency_ms       REAL,
    latency_overhead_ms   REAL,
    judge_engine          TEXT,
    notes                 TEXT,
    PRIMARY KEY (run_id, config)
);

CREATE TABLE IF NOT EXISTS evaluation_results (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id            TEXT NOT NULL,
    case_id           TEXT NOT NULL,
    category          TEXT NOT NULL,
    config            TEXT NOT NULL,
    decision          TEXT NOT NULL,
    executed          INTEGER NOT NULL DEFAULT 0,
    risk_score        INTEGER,
    latency_ms        REAL,
    expected_decision TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_log(decision);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_eval_results_run ON evaluation_results(run_id, config);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
