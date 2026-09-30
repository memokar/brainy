"""Write-Vorschlaege (Approval-gated Knowledge-Writes).

Ein Agent (z.B. ChatGPT) schlaegt eine Aenderung an einem Knowledge-Dokument VOR
(create_proposal). Ein Owner/Editor gibt sie frei (apply_proposal) -> erst dann wird
knowledge.write_document ausgefuehrt (Git-Commit, Secret-Guard, Audit). Der
Vorschlagende braucht KEIN can_write; er braucht nur Leserecht im Ziel-Space.
Selbstfreigabe ist gesperrt (ausser ADMIN). Alle Entscheidungen sind auditiert.
"""
import secrets as _secrets

from . import acl
from . import audit
from . import capabilities as cap
from . import knowledge
from . import paths
from .errors import BrainyError, InvalidState, NotFound, PermissionDenied, SecretDetected
from .util import now_iso, pid

STATUS_PENDING = "PENDING"
STATUS_APPLIED = "APPLIED"
STATUS_REJECTED = "REJECTED"
STATUS_FAILED = "FAILED"


def _gen_id():
    return "wp_" + _secrets.token_hex(6)


def _name(conn, principal_id):
    p = acl.get_principal(conn, principal_id)
    return (p or {}).get("name") or ("principal-%s" % principal_id)


def get_proposal(conn, proposal_id):
    r = conn.execute("SELECT * FROM write_proposals WHERE proposal_id=?",
                     (proposal_id,)).fetchone()
    return dict(r) if r else None


def list_proposals(conn, status=None, limit=100):
    if status:
        rows = conn.execute(
            "SELECT * FROM write_proposals WHERE status=? ORDER BY id DESC LIMIT ?",
            (status, limit))
    else:
        rows = conn.execute(
            "SELECT * FROM write_proposals ORDER BY id DESC LIMIT ?", (limit,))
    return [dict(r) for r in rows]


def create_proposal(conn, proposer, path, content, commit_message,
                    expected_git_commit=None, root=None):
    """Legt einen PENDING-Vorschlag an. Validiert Pfad (kanonische .md), verlangt
    Leserecht im Ziel-Space und lehnt mutmassliche Secrets sofort ab (nie speichern)."""
    proposer_id = pid(proposer)
    # 1) Pfad validieren (nur kanonische .md; Traversal/Escape/.git werden abgelehnt)
    rel, _abs = paths.resolve(path, root=root)
    sp = paths.space_for_path(rel)
    # 2) Vorschlagen setzt Leserecht im Ziel-Space voraus (Rolle-Ceiling + Space-ACL)
    cap.require(conn, proposer, cap.KNOWLEDGE_READ, sp)
    # 3) Pflichtfelder
    if not isinstance(content, str) or content.strip() == "":
        raise BrainyError("leerer/ungueltiger content")
    if not commit_message or not str(commit_message).strip():
        raise BrainyError("commit_message erforderlich")
    # 4) Secret-Guard schon beim Vorschlag -> Secrets landen nie in der DB
    hit = knowledge.scan_secrets(content)
    if hit:
        audit.log(conn, proposer_id, "write_proposal_rejected_secret", "proposal",
                  None, None, {"pattern": hit, "path": rel}, commit=True)   # KEIN Wert
        raise SecretDetected("mutmassliches Secret im content -> Vorschlag abgelehnt")
    proposal_id = _gen_id()
    conn.execute(
        "INSERT INTO write_proposals(proposal_id, proposer_id, space, path, content, "
        "commit_message, expected_git_commit, status, created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (proposal_id, proposer_id, sp, rel, content, str(commit_message),
         expected_git_commit, STATUS_PENDING, now_iso()))
    audit.log(conn, proposer_id, "write_proposal_created", "proposal", proposal_id,
              None, {"space": sp, "path": rel})   # KEIN content ins Audit
    conn.commit()
    return get_proposal(conn, proposal_id)


def _require_approver(conn, approver, space):
    # can_approve im Ziel-Space: nur ADMIN/EDITOR-Rolle mit ACL. AGENT/READER nie.
    cap.require(conn, approver, cap.TASK_APPROVE, space)


def apply_proposal(conn, approver, proposal_id, root=None, note=None):
    """Freigabe: fuehrt den echten write_document als Freigebender aus. Idempotent
    (bereits APPLIED -> unveraendert zurueck). Selbstfreigabe gesperrt (ausser ADMIN)."""
    approver_id = pid(approver)
    p = get_proposal(conn, proposal_id)
    if not p:
        raise NotFound("proposal %s" % proposal_id)
    if p["status"] == STATUS_APPLIED:
        return p
    if p["status"] != STATUS_PENDING:
        raise InvalidState("proposal %s ist %s (nicht PENDING)" % (proposal_id, p["status"]))
    _require_approver(conn, approver, p["space"])
    if approver_id == p["proposer_id"] and not acl.is_admin(conn, approver_id):
        raise PermissionDenied("Vorschlagender darf nicht selbst freigeben")
    msg = "%s\n\n[Brainy-Vorschlag %s von %s, freigegeben von %s]" % (
        p["commit_message"], proposal_id, _name(conn, p["proposer_id"]),
        _name(conn, approver_id))
    try:
        res = knowledge.write_document(conn, approver_id, p["path"], p["content"],
                                       p["expected_git_commit"], msg, root=root)
    except Exception as e:
        conn.execute("UPDATE write_proposals SET status=?, decided_by=?, decided_at=?, "
                     "error=? WHERE proposal_id=?",
                     (STATUS_FAILED, approver_id, now_iso(), str(e)[:200], proposal_id))
        audit.log(conn, approver_id, "write_proposal_failed", "proposal", proposal_id,
                  None, {"err": str(e)[:120]})
        conn.commit()
        raise
    conn.execute("UPDATE write_proposals SET status=?, decided_by=?, decided_at=?, "
                 "decision_note=?, result_commit=? WHERE proposal_id=?",
                 (STATUS_APPLIED, approver_id, now_iso(), note, res.get("commit"),
                  proposal_id))
    audit.log(conn, approver_id, "write_proposal_applied", "proposal", proposal_id, None,
              {"space": p["space"], "path": p["path"], "commit": res.get("commit")})
    conn.commit()
    return get_proposal(conn, proposal_id)


def reject_proposal(conn, approver, proposal_id, note=None):
    """Ablehnung: kein Write. Idempotent (bereits REJECTED -> unveraendert)."""
    approver_id = pid(approver)
    p = get_proposal(conn, proposal_id)
    if not p:
        raise NotFound("proposal %s" % proposal_id)
    if p["status"] == STATUS_REJECTED:
        return p
    if p["status"] != STATUS_PENDING:
        raise InvalidState("proposal %s ist %s (nicht PENDING)" % (proposal_id, p["status"]))
    _require_approver(conn, approver, p["space"])
    conn.execute("UPDATE write_proposals SET status=?, decided_by=?, decided_at=?, "
                 "decision_note=? WHERE proposal_id=?",
                 (STATUS_REJECTED, approver_id, now_iso(), note, proposal_id))
    audit.log(conn, approver_id, "write_proposal_rejected", "proposal", proposal_id, None,
              {"space": p["space"], "path": p["path"]})
    conn.commit()
    return get_proposal(conn, proposal_id)
