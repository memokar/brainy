-- 007_resource_claims.sql : Ressourcen-Claims (0.2.0)
-- Befristete, exklusive Reservierung beliebiger Ressourcen (freier String-Key je Space,
-- z.B. "repo:app/src/auth/**"). Gleiches Prinzip wie Task-Claims: atomarer Claim, Lease
-- mit Ablauf, claim_token, renew/release. Genau EINE Zeile je (space_id, resource_key);
-- released_at IS NOT NULL ODER abgelaufener lease_until => wieder claimbar. Alles auditiert.
CREATE TABLE IF NOT EXISTS resource_claims (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  space_id      INTEGER NOT NULL REFERENCES spaces(id),
  resource_key  TEXT    NOT NULL,
  holder_id     INTEGER NOT NULL REFERENCES principals(id),
  claim_token   TEXT    NOT NULL,
  claimed_at    TEXT    NOT NULL,
  lease_until   TEXT    NOT NULL,
  note          TEXT,
  released_at   TEXT,
  UNIQUE(space_id, resource_key)
);
CREATE INDEX IF NOT EXISTS idx_resource_claims_lookup
  ON resource_claims(space_id, released_at, lease_until);
