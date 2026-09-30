-- Brainy schema v5 (Phase O6A): eingebetteter OAuth-2.1-Authorization-Server (MCP-kompatibel).
-- KEINE Klartext-Secrets: Codes/Tokens werden nur als sha256-Hash gespeichert.

-- Dynamic Client Registration (RFC 7591). Public Clients (PKCE) -> kein Client-Secret.
CREATE TABLE oauth_clients (
    client_id                  TEXT PRIMARY KEY,
    client_name                TEXT,
    redirect_uris              TEXT NOT NULL,                 -- JSON array (exakte URIs)
    grant_types                TEXT NOT NULL DEFAULT 'authorization_code refresh_token',
    scope                      TEXT,                          -- erlaubte Scopes (space-sep)
    token_endpoint_auth_method TEXT NOT NULL DEFAULT 'none',
    created_at                 TEXT NOT NULL,
    created_via                TEXT NOT NULL DEFAULT 'dcr'
);

-- Kurzlebige Authorization Codes (single-use, PKCE-gebunden).
CREATE TABLE oauth_auth_codes (
    code_hash             TEXT PRIMARY KEY,                   -- sha256(code)
    client_id             TEXT NOT NULL,
    principal_id          INTEGER NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    redirect_uri          TEXT NOT NULL,
    scope                 TEXT,
    code_challenge        TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL DEFAULT 'S256',
    expires_at            TEXT NOT NULL,
    used_at               TEXT,
    created_at            TEXT NOT NULL
);

-- Access-/Refresh-Tokens (nur Hash gespeichert; widerrufbar).
CREATE TABLE oauth_tokens (
    token_hash    TEXT PRIMARY KEY,                           -- sha256(token)
    token_type    TEXT NOT NULL,                              -- 'access' | 'refresh'
    client_id      TEXT NOT NULL,
    principal_id   INTEGER NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    scope          TEXT,
    expires_at     TEXT,
    revoked_at     TEXT,
    auth_code_hash TEXT,                                       -- Herkunfts-Code (Reuse-Revocation)
    created_at     TEXT NOT NULL
);
CREATE INDEX idx_oauth_tokens_principal ON oauth_tokens(principal_id);
CREATE INDEX idx_oauth_tokens_client    ON oauth_tokens(client_id);
CREATE INDEX idx_oauth_codes_client     ON oauth_auth_codes(client_id);
