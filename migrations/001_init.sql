-- Brainy Core schema v1 (Phase A). Keine Secrets in diesen Tabellen.

CREATE TABLE spaces (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key         TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE principals (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    principal_type TEXT NOT NULL,             -- human | agent | service
    name           TEXT NOT NULL UNIQUE,
    role           TEXT NOT NULL,             -- ADMIN | EDITOR | AGENT | READER
    active         INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT NOT NULL
);

CREATE TABLE space_acl (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    space_id           INTEGER NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    principal_id       INTEGER NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    can_read           INTEGER NOT NULL DEFAULT 0,
    can_write          INTEGER NOT NULL DEFAULT 0,
    can_create_tasks   INTEGER NOT NULL DEFAULT 0,
    can_claim_tasks    INTEGER NOT NULL DEFAULT 0,
    can_complete_tasks INTEGER NOT NULL DEFAULT 0,
    can_manage_space   INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    UNIQUE(space_id, principal_id)
);

CREATE TABLE tasks (
    task_id        TEXT PRIMARY KEY,
    title          TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    space_id       INTEGER NOT NULL REFERENCES spaces(id),
    target_ref     TEXT,                       -- project/system/tool
    type           TEXT NOT NULL DEFAULT 'chore',
    status         TEXT NOT NULL DEFAULT 'OPEN',
    priority       TEXT NOT NULL DEFAULT 'P3',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    created_by     TEXT,
    assigned_to    TEXT,
    claimed_by     TEXT,
    claimed_at     TEXT,
    lease_until    TEXT,
    claim_token    TEXT,
    completed_at   TEXT,
    result         TEXT,
    result_refs    TEXT,                        -- JSON array
    dependencies   TEXT,                        -- JSON array of task_id
    tags           TEXT,                        -- JSON array
    source_sot     TEXT,
    retry_count    INTEGER NOT NULL DEFAULT 0,
    failure_reason TEXT
);

CREATE TABLE audit_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    actor       TEXT,
    action      TEXT NOT NULL,
    object_type TEXT,
    object_id   TEXT,
    space_id    INTEGER,
    metadata    TEXT                             -- JSON, keine Secrets/Payloads
);

CREATE INDEX idx_tasks_status     ON tasks(status);
CREATE INDEX idx_tasks_space      ON tasks(space_id);
CREATE INDEX idx_tasks_claimed_by ON tasks(claimed_by);
CREATE INDEX idx_tasks_lease      ON tasks(lease_until);
CREATE INDEX idx_audit_ts         ON audit_events(timestamp);

-- Audit ist append-only: UPDATE/DELETE werden hart abgelehnt.
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
