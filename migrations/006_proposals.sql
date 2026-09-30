-- 006_proposals.sql : Write-Vorschlaege (Approval-gated Knowledge-Writes)
-- Ein Agent (z.B. ChatGPT) schlaegt eine Knowledge-Aenderung VOR; ein Owner/Editor
-- gibt sie frei -> erst dann wird knowledge.write_document ausgefuehrt (Git-Commit).
-- Kein direktes can_write fuer den Vorschlagenden noetig. Alles auditiert.
CREATE TABLE IF NOT EXISTS write_proposals (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  proposal_id         TEXT NOT NULL UNIQUE,
  proposer_id         INTEGER NOT NULL REFERENCES principals(id),
  space               TEXT NOT NULL,
  path                TEXT NOT NULL,
  content             TEXT NOT NULL,
  commit_message      TEXT NOT NULL,
  expected_git_commit TEXT,
  status              TEXT NOT NULL DEFAULT 'PENDING',  -- PENDING|APPLIED|REJECTED|FAILED
  created_at          TEXT NOT NULL,
  decided_by          INTEGER REFERENCES principals(id),
  decided_at          TEXT,
  decision_note       TEXT,
  result_commit       TEXT,
  error               TEXT,
  tg_message_id       TEXT
);
CREATE INDEX IF NOT EXISTS idx_write_proposals_status ON write_proposals(status);
CREATE INDEX IF NOT EXISTS idx_write_proposals_proposer ON write_proposals(proposer_id);
