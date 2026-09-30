-- Brainy schema v4 (Phase O2): Agent-Registry, Execution-Jobs, System-Settings
-- (globaler Dispatcher-Kill-Switch). Additiv. KEINE Secrets in diesen Tabellen.

-- Globale Einstellungen (u. a. Dispatcher-Kill-Switch). Default: Dispatcher AUS.
CREATE TABLE system_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT,
    updated_at TEXT
);
INSERT INTO system_settings(key, value, updated_at)
VALUES ('dispatcher_enabled', 'false', '2026-08-12T00:00:00+00:00');

-- Agent-Registry (Worker-Steuerung). Capabilities/Spaces werden aus der Principal-ACL
-- abgeleitet (nicht dupliziert). KEIN Secret/Token hier — nur config_ref (Verweis).
CREATE TABLE agents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_name      TEXT NOT NULL UNIQUE,
    principal_id    INTEGER NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    worker_type     TEXT NOT NULL,                 -- MOCK | CLAUDE_ADAPTER | ...
    enabled         INTEGER NOT NULL DEFAULT 0,    -- Default: NICHT runnable
    max_concurrency INTEGER NOT NULL DEFAULT 1,
    config_ref      TEXT,                          -- KEIN Secret; nur Verweis
    last_seen       TEXT,
    status          TEXT NOT NULL DEFAULT 'registered',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

-- Execution-Jobs: eine Ausfuehrung eines Tasks durch einen Agent-Worker.
CREATE TABLE execution_jobs (
    job_id             TEXT PRIMARY KEY,
    task_id            TEXT NOT NULL REFERENCES tasks(task_id),
    agent_principal_id INTEGER NOT NULL,
    worker_type        TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'QUEUED',   -- QUEUED/STARTING/RUNNING/
                                                          -- SUCCEEDED/FAILED/TIMED_OUT/CANCELLED
    created_at         TEXT NOT NULL,
    started_at         TEXT,
    finished_at        TEXT,
    heartbeat_at       TEXT,
    lease_until        TEXT,
    attempt            INTEGER NOT NULL DEFAULT 1,
    max_attempts       INTEGER NOT NULL DEFAULT 3,
    error_code         TEXT,
    error_summary      TEXT,
    result_ref         TEXT,
    dispatch_token     TEXT,             -- interner Task-Claim-Token; NIE in UI/MCP
    created_by         TEXT
);

-- Nur EIN aktiver Execution-Job pro Task (verhindert Doppel-Dispatch).
CREATE UNIQUE INDEX ux_active_job_per_task ON execution_jobs(task_id)
    WHERE status IN ('QUEUED', 'STARTING', 'RUNNING');
CREATE INDEX idx_jobs_status ON execution_jobs(status);
CREATE INDEX idx_jobs_agent  ON execution_jobs(agent_principal_id);
