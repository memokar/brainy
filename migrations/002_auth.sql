-- Brainy schema v2 (Phase C): Identity/Token/External-Identity. Keine Secrets im Klartext.

ALTER TABLE principals ADD COLUMN updated_at TEXT;
ALTER TABLE principals ADD COLUMN metadata TEXT;      -- JSON, KEINE Secrets

CREATE TABLE service_tokens (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id     TEXT NOT NULL UNIQUE,                 -- oeffentlicher Identifier (KEIN Secret)
    principal_id INTEGER NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL,                        -- sha256(secret); NIE Klartext
    description  TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    expires_at   TEXT,
    revoked_at   TEXT,
    last_used_at TEXT,
    active       INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_tokens_principal ON service_tokens(principal_id);
CREATE INDEX idx_tokens_tokenid   ON service_tokens(token_id);

CREATE TABLE external_identities (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    provider         TEXT NOT NULL,                    -- z.B. tool_portal
    external_subject TEXT NOT NULL,                    -- SSO-Subject (keine Secrets)
    principal_id     INTEGER NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    created_at       TEXT NOT NULL,
    UNIQUE(provider, external_subject)
);
