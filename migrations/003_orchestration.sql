-- Brainy schema v3 (Phase O1): AUTO/REVIEW/APPROVAL-Governance, Risiko-/Action-Klassen,
-- Review-/Approval-Gates, Dependencies, Routing-Grundlage. Additive Migration (ALTER ADD).

-- ---- Governance-/Policy-Felder auf tasks ----
ALTER TABLE tasks ADD COLUMN execution_mode TEXT NOT NULL DEFAULT 'REVIEW';   -- requested
ALTER TABLE tasks ADD COLUMN effective_execution_mode TEXT;                    -- nach Policy
ALTER TABLE tasks ADD COLUMN risk_level TEXT NOT NULL DEFAULT 'MEDIUM';
ALTER TABLE tasks ADD COLUMN action_class TEXT;                                -- optional
ALTER TABLE tasks ADD COLUMN approval_required INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tasks ADD COLUMN policy_rule TEXT;                                 -- Eskalationsgrund
-- Review-Gate
ALTER TABLE tasks ADD COLUMN reviewed_by TEXT;
ALTER TABLE tasks ADD COLUMN reviewed_at TEXT;
ALTER TABLE tasks ADD COLUMN review_note TEXT;
-- Approval-Gate
ALTER TABLE tasks ADD COLUMN approved_by TEXT;
ALTER TABLE tasks ADD COLUMN approved_at TEXT;
ALTER TABLE tasks ADD COLUMN approval_note TEXT;
-- Routing-Grundlage
ALTER TABLE tasks ADD COLUMN preferred_agent TEXT;             -- principal_id (String) o. NULL
ALTER TABLE tasks ADD COLUMN required_capabilities TEXT;       -- JSON array von Capability-Namen

-- ---- Review-/Approve-ACL-Spalten ----
ALTER TABLE space_acl ADD COLUMN can_review  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE space_acl ADD COLUMN can_approve INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
