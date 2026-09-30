"""Task-Engine: create/get/list, atomic claim/lease/renew/release, idempotentes
complete/fail, generische Statusuebergaenge. ACL wird pro Aktion erzwungen.

Kern-Invarianten:
- Nur EIN Agent verarbeitet einen Task gleichzeitig (atomic UPDATE + claim_token).
- Abgelaufener Lease -> Task wieder claimbar; neuer Claim => neues claim_token
  => alter (stale) Token kann nicht mehr complete/fail/renew.
- complete/fail sind idempotent (No-op bei bereits erreichtem Endzustand mit gleichem Token).
"""
import secrets
import uuid

from . import acl
from . import audit
from . import capabilities as cap
from . import models as m
from . import orchestration as orch
from . import spaces
from .errors import ClaimConflict, InvalidState, NotFound, PermissionDenied, StaleToken
from .util import dumps, iso_plus, loads, now_iso, pid

DEFAULT_LEASE_SECONDS = 900  # 15 Minuten


def _row(conn, task_id):
    r = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
    return dict(r) if r else None


def _hydrate(d):
    if d is None:
        return None
    d = dict(d)
    for f in ("result_refs", "dependencies", "tags", "required_capabilities"):
        d[f] = loads(d.get(f), [])
    return d


def get_task(conn, task_id):
    return _hydrate(_row(conn, task_id))


def list_tasks(conn, space=None, status=None, type=None, assigned_to=None,
               claimed_by=None, limit=500):
    sql = "SELECT * FROM tasks WHERE 1=1"
    args = []
    if space is not None:
        sid = spaces.get_space(conn, space)
        if not sid:
            raise NotFound("space nicht gefunden: %s" % space)
        sql += " AND space_id=?"; args.append(sid["id"])
    if status:
        sql += " AND status=?"; args.append(status)
    if type:
        sql += " AND type=?"; args.append(type)
    if assigned_to:
        sql += " AND assigned_to=?"; args.append(str(assigned_to))
    if claimed_by:
        sql += " AND claimed_by=?"; args.append(str(claimed_by))
    sql += " ORDER BY created_at DESC LIMIT ?"; args.append(limit)
    return [_hydrate(dict(r)) for r in conn.execute(sql, args)]


def status_counts(conn, space_keys=None):
    """Zaehlt Tasks je Status (fuer Dashboard). space_keys=None -> alle Spaces;
    sonst nur die genannten (lesbaren) Spaces. Reine Aggregation, kein Nebeneffekt."""
    counts = {s: 0 for s in m.STATUSES}
    sql = "SELECT status, COUNT(*) AS c FROM tasks"
    args = []
    if space_keys is not None:
        ids = []
        for k in space_keys:
            sp = spaces.get_space(conn, k)
            if sp:
                ids.append(sp["id"])
        if not ids:
            return counts
        sql += " WHERE space_id IN (%s)" % ",".join("?" * len(ids))
        args = ids
    sql += " GROUP BY status"
    for r in conn.execute(sql, args):
        counts[r["status"]] = r["c"]
    return counts


def create_task(conn, principal_id, space, title, type="chore", priority="P3",
                description="", target_ref=None, assigned_to=None, source_sot=None,
                tags=None, dependencies=None, status=m.OPEN,
                execution_mode=None, risk_level=None, action_class=None,
                preferred_agent=None, required_capabilities=None):
    principal_id = pid(principal_id)
    sp = spaces.get_space(conn, space)
    if not sp:
        raise NotFound("space nicht gefunden: %s" % space)
    acl.require(conn, principal_id, sp["id"], m.CAP_CREATE_TASKS)
    if status not in (m.OPEN, m.READY):
        raise InvalidState("neuer Task muss OPEN oder READY sein")
    if type not in m.TASK_TYPES:
        raise InvalidState("unbekannter type: %s" % type)
    if priority not in m.PRIORITIES:
        raise InvalidState("unbekannte priority: %s" % priority)

    # --- Governance-Policy zentral bewerten (kanonische Schicht) ---
    pol = orch.evaluate_policy(execution_mode or m.DEFAULT_EXECUTION_MODE,
                               risk_level, action_class)
    pref = None
    if preferred_agent:
        pp = acl.get_principal(conn, pid(preferred_agent)) if str(preferred_agent).isdigit() \
            else _principal_by_name(conn, preferred_agent)
        if not pp:
            raise NotFound("preferred_agent nicht gefunden: %s" % preferred_agent)
        pref = str(pp["id"])
    reqcaps = list(required_capabilities or [])

    tid = uuid.uuid4().hex
    now = now_iso()
    conn.execute(
        "INSERT INTO tasks(task_id, title, description, space_id, target_ref, type, "
        "status, priority, created_at, updated_at, created_by, assigned_to, result_refs, "
        "dependencies, tags, source_sot, retry_count, execution_mode, "
        "effective_execution_mode, risk_level, action_class, approval_required, policy_rule, "
        "preferred_agent, required_capabilities) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?,?,?,?,?,?)",
        (tid, title, description, sp["id"], target_ref, type, status, priority, now, now,
         str(principal_id), assigned_to, dumps([]), dumps(dependencies or []),
         dumps(tags or []), source_sot, pol["requested"], pol["effective"], pol["risk"],
         pol["action_class"], 1 if pol["approval_required"] else 0, pol["rule"],
         pref, dumps(reqcaps)),
    )
    audit.log(conn, principal_id, "task_created", "task", tid, sp["id"],
              {"status": status, "type": type, "priority": priority})
    audit.log(conn, principal_id, "task_policy_evaluated", "task", tid, sp["id"],
              {"requested": pol["requested"], "effective": pol["effective"],
               "risk": pol["risk"], "action_class": pol["action_class"],
               "rule": pol["rule"]})
    if pol["escalated"]:
        audit.log(conn, principal_id, "task_policy_escalated", "task", tid, sp["id"],
                  {"requested": pol["requested"], "effective": pol["effective"],
                   "risk": pol["risk"], "action_class": pol["action_class"],
                   "policy_rule": pol["rule"]})
    conn.commit()
    return get_task(conn, tid)


def _principal_by_name(conn, name):
    r = conn.execute("SELECT * FROM principals WHERE name=?", (str(name),)).fetchone()
    return dict(r) if r else None


# ---------------------------------------------------------------- Dependencies
def _deps_of(task):
    d = task.get("dependencies")
    if isinstance(d, str):
        return loads(d, [])
    return d or []


def deps_state(conn, task):
    """satisfied | pending | broken. Ohne Dependencies -> satisfied.
    COMPLETED = erfuellt; FAILED/CANCELLED/REJECTED/fehlend = broken; sonst pending."""
    deps = _deps_of(task)
    if not deps:
        return "satisfied"
    broken = pending = False
    for d in deps:
        r = _row(conn, d)
        if not r:
            broken = True
            continue
        st = r["status"]
        if st == m.COMPLETED:
            continue
        if st in (m.FAILED, m.CANCELLED, m.REJECTED):
            broken = True
        else:
            pending = True
    if broken:
        return "broken"
    if pending:
        return "pending"
    return "satisfied"


def _refresh_dependents(conn, actor, task_id):
    """Nach Statuswechsel von task_id: abhaengige Tasks blocken/freigeben (kein Claiming).
    Ohne eigenen Commit -> laeuft in der Transaktion des Aufrufers."""
    rows = conn.execute("SELECT * FROM tasks WHERE dependencies LIKE ?",
                        ("%" + task_id + "%",)).fetchall()
    for r in rows:
        r = dict(r)
        if task_id not in _deps_of(r):
            continue
        st = deps_state(conn, r)
        cur = r["status"]
        if st == "broken" and cur in (m.OPEN, m.READY):
            # Diagnose-Pflicht: BLOCKED nie ohne failure_reason (kein stiller Verlust).
            conn.execute("UPDATE tasks SET status='BLOCKED', failure_reason=?, updated_at=? "
                         "WHERE task_id=?",
                         ("dependency_broken: blockiert durch %s" % task_id, now_iso(),
                          r["task_id"]))
            audit.log(conn, actor, "dependency_blocked", "task", r["task_id"],
                      r["space_id"], {"blocked_by": task_id})
        elif st == "satisfied" and cur == m.BLOCKED:
            # Wieder freigegeben: alten Blockier-Grund entfernen.
            conn.execute("UPDATE tasks SET status='READY', failure_reason=NULL, updated_at=? "
                         "WHERE task_id=?",
                         (now_iso(), r["task_id"]))
            audit.log(conn, actor, "dependency_released", "task", r["task_id"],
                      r["space_id"], {"released_by": task_id})


def set_status(conn, principal_id, task_id, new_status):
    """Generischer Statusuebergang (OPEN/READY/BLOCKED/CANCELLED, FAILED->READY).
    CLAIMED/IN_PROGRESS/COMPLETED/FAILED werden NUR ueber die Engine-Funktionen gesetzt."""
    principal_id = pid(principal_id)
    task = _row(conn, task_id)
    if not task:
        raise NotFound(task_id)
    acl.require(conn, principal_id, task["space_id"], m.CAP_CREATE_TASKS)
    cur = task["status"]
    if new_status in m.ENGINE_ONLY:
        raise InvalidState("Status %s nur ueber claim/complete/fail setzbar" % new_status)
    if new_status not in m.VALID_TRANSITIONS.get(cur, set()):
        raise InvalidState("Uebergang %s -> %s nicht erlaubt" % (cur, new_status))
    conn.execute("UPDATE tasks SET status=?, updated_at=? WHERE task_id=?",
                 (new_status, now_iso(), task_id))
    action = "task_ready" if new_status == m.READY else (
        "task_blocked" if new_status == m.BLOCKED else (
            "task_unblocked" if cur == m.BLOCKED else (
                "task_cancelled" if new_status == m.CANCELLED else "task_status_changed")))
    audit.log(conn, principal_id, action, "task", task_id, task["space_id"],
              {"from": cur, "to": new_status})
    if new_status in (m.CANCELLED, m.REJECTED):
        _refresh_dependents(conn, principal_id, task_id)
    conn.commit()
    return get_task(conn, task_id)


def claim_task(conn, principal_id, task_id, lease_seconds=DEFAULT_LEASE_SECONDS):
    """Atomischer Claim. Erfolg nur, wenn READY ODER (aktiver Claim mit abgelaufenem
    Lease). Vergibt neues claim_token. Genau EIN paralleler Claimer gewinnt."""
    principal_id = pid(principal_id)
    task = _row(conn, task_id)
    if not task:
        raise NotFound(task_id)
    acl.require(conn, principal_id, task["space_id"], m.CAP_CLAIM)
    # Dependency-Gate: nicht claimbar, solange Voraussetzungen offen/kaputt sind.
    dep = deps_state(conn, task)
    if dep != "satisfied":
        if dep == "broken" and task["status"] not in m.TERMINAL and task["status"] != m.BLOCKED:
            # Diagnose-Pflicht: BLOCKED nie ohne failure_reason (kein stiller Verlust).
            conn.execute("UPDATE tasks SET status='BLOCKED', failure_reason=?, updated_at=? "
                         "WHERE task_id=?",
                         ("dependency_broken: Voraussetzungen nicht erfuellbar", now_iso(),
                          task_id))
            audit.log(conn, principal_id, "dependency_blocked", "task", task_id,
                      task["space_id"], {"reason": "dependency_broken"})
            conn.commit()
        raise ClaimConflict("Dependencies nicht erfuellt (%s) fuer %s" % (dep, task_id))
    now = now_iso()
    lease_until = iso_plus(lease_seconds)
    token = secrets.token_hex(16)
    cur = conn.execute(
        "UPDATE tasks SET status='CLAIMED', claimed_by=?, claimed_at=?, lease_until=?, "
        "claim_token=?, updated_at=? "
        "WHERE task_id=? AND ("
        "  status='READY' "
        "  OR (status IN ('CLAIMED','IN_PROGRESS') AND lease_until IS NOT NULL "
        "      AND lease_until < ?))",
        (str(principal_id), now, lease_until, token, now, task_id, now),
    )
    if cur.rowcount != 1:
        conn.rollback()
        raise ClaimConflict("Task %s ist nicht claimbar (Status %s)" % (task_id, task["status"]))
    audit.log(conn, principal_id, "task_claimed", "task", task_id, task["space_id"],
              {"lease_until": lease_until})
    conn.commit()
    return {"task_id": task_id, "claim_token": token, "lease_until": lease_until}


def start_progress(conn, principal_id, task_id, claim_token):
    """Optionaler Uebergang CLAIMED -> IN_PROGRESS (Arbeit begonnen)."""
    principal_id = pid(principal_id)
    cur = conn.execute(
        "UPDATE tasks SET status='IN_PROGRESS', updated_at=? "
        "WHERE task_id=? AND claimed_by=? AND claim_token=? AND status='CLAIMED' "
        "AND lease_until > ?",
        (now_iso(), task_id, str(principal_id), claim_token, now_iso()),
    )
    if cur.rowcount != 1:
        conn.rollback()
        raise StaleToken("kein gueltiger aktiver Claim fuer %s" % task_id)
    task = _row(conn, task_id)
    audit.log(conn, principal_id, "task_in_progress", "task", task_id, task["space_id"])
    conn.commit()
    return get_task(conn, task_id)


def renew_claim(conn, principal_id, task_id, claim_token, lease_seconds=DEFAULT_LEASE_SECONDS):
    """Verlaengert den Lease. Nur aktueller Owner + gueltiges (nicht abgelaufenes) Token."""
    principal_id = pid(principal_id)
    now = now_iso()
    lease_until = iso_plus(lease_seconds)
    cur = conn.execute(
        "UPDATE tasks SET lease_until=?, updated_at=? "
        "WHERE task_id=? AND claimed_by=? AND claim_token=? "
        "AND status IN ('CLAIMED','IN_PROGRESS') AND lease_until > ?",
        (lease_until, now, task_id, str(principal_id), claim_token, now),
    )
    if cur.rowcount != 1:
        conn.rollback()
        raise StaleToken("renew abgelehnt (stale/abgelaufen/kein Owner) fuer %s" % task_id)
    task = _row(conn, task_id)
    audit.log(conn, principal_id, "task_claim_renewed", "task", task_id, task["space_id"],
              {"lease_until": lease_until})
    conn.commit()
    return {"task_id": task_id, "lease_until": lease_until}


def release_task(conn, principal_id, task_id, claim_token):
    """Gibt einen eigenen Claim frei -> Status READY, Claim-Felder geleert."""
    principal_id = pid(principal_id)
    cur = conn.execute(
        "UPDATE tasks SET status='READY', claimed_by=NULL, claimed_at=NULL, "
        "lease_until=NULL, claim_token=NULL, updated_at=? "
        "WHERE task_id=? AND claimed_by=? AND claim_token=? "
        "AND status IN ('CLAIMED','IN_PROGRESS')",
        (now_iso(), task_id, str(principal_id), claim_token),
    )
    if cur.rowcount != 1:
        conn.rollback()
        raise StaleToken("release abgelehnt (kein aktueller Claim) fuer %s" % task_id)
    task = _row(conn, task_id)
    audit.log(conn, principal_id, "task_released", "task", task_id, task["space_id"])
    conn.commit()
    return get_task(conn, task_id)


def effective_mode(task):
    return task.get("effective_execution_mode") or task.get("execution_mode") \
        or m.DEFAULT_EXECUTION_MODE


def complete_task(conn, principal_id, task_id, claim_token, result=None, result_refs=None):
    """Abschluss durch den Claim-Owner — **governance-gated**:
      AUTO     -> COMPLETED (+ Dependents freigeben)
      REVIEW   -> AWAITING_REVIEW (Reviewer muss bestaetigen)
      APPROVAL -> AWAITING_APPROVAL (Approver muss freigeben)
    Ein Agent kann das Gate NICHT per result-Wert umgehen. Idempotent."""
    principal_id = pid(principal_id)
    task = _row(conn, task_id)
    if not task:
        raise NotFound(task_id)
    acl.require(conn, principal_id, task["space_id"], m.CAP_COMPLETE)
    eff = effective_mode(task)
    if eff == m.EXEC_AUTO:
        target = m.COMPLETED
    elif eff == m.EXEC_REVIEW:
        target = m.AWAITING_REVIEW
    else:
        # APPROVAL: erste Ausfuehrung -> Gate (AWAITING_APPROVAL); nach erfolgtem
        # Approval (approved_at gesetzt) darf die freigegebene Aktion abschliessen.
        target = m.COMPLETED if task["approved_at"] else m.AWAITING_APPROVAL

    # Idempotenz: Ziel bereits erreicht durch denselben Owner -> No-op-Erfolg.
    if task["status"] == target:
        if target == m.COMPLETED and task["claim_token"] == claim_token:
            return get_task(conn, task_id)
        if target in (m.AWAITING_REVIEW, m.AWAITING_APPROVAL) \
                and task["claimed_by"] == str(principal_id):
            return get_task(conn, task_id)
    if task["status"] == m.COMPLETED and target != m.COMPLETED:
        raise StaleToken("Task bereits abgeschlossen")

    now = now_iso()
    refs = dumps(result_refs if result_refs is not None else [])
    if target == m.COMPLETED:
        cur = conn.execute(
            "UPDATE tasks SET status='COMPLETED', completed_at=?, result=?, result_refs=?, "
            "lease_until=NULL, updated_at=? WHERE task_id=? AND claimed_by=? AND claim_token=? "
            "AND status IN ('CLAIMED','IN_PROGRESS')",
            (now, result, refs, now, task_id, str(principal_id), claim_token))
    else:
        # Gate: Arbeit fertig, Claim wird freigegeben (lease/token geleert), Owner bleibt vermerkt.
        cur = conn.execute(
            "UPDATE tasks SET status=?, result=?, result_refs=?, lease_until=NULL, "
            "claim_token=NULL, updated_at=? WHERE task_id=? AND claimed_by=? AND claim_token=? "
            "AND status IN ('CLAIMED','IN_PROGRESS')",
            (target, result, refs, now, task_id, str(principal_id), claim_token))
    if cur.rowcount != 1:
        conn.rollback()
        raise StaleToken("complete abgelehnt (stale/kein aktiver Claim) fuer %s" % task_id)
    if target == m.COMPLETED:
        audit.log(conn, principal_id, "task_completed", "task", task_id, task["space_id"])
        _refresh_dependents(conn, principal_id, task_id)
    elif target == m.AWAITING_REVIEW:
        audit.log(conn, principal_id, "task_awaiting_review", "task", task_id,
                  task["space_id"], {"mode": eff})
    else:
        audit.log(conn, principal_id, "task_awaiting_approval", "task", task_id,
                  task["space_id"], {"mode": eff, "approval_required": 1})
    conn.commit()
    return get_task(conn, task_id)


# ---------------------------------------------------------------- Review / Approval Gates
def _actor_is_admin(conn, principal_id):
    return acl.is_admin(conn, principal_id)


def _no_self_gate(conn, task, principal_id):
    """Der ausfuehrende Agent/Owner darf sich nicht selbst freigeben (ausser ADMIN)."""
    if task["claimed_by"] == str(principal_id) and not _actor_is_admin(conn, principal_id):
        raise PermissionDenied("Selbstfreigabe des ausfuehrenden Principals nicht erlaubt")


def review_task(conn, principal_id, task_id, decision, note=None, rework=False):
    """Reviewer bestaetigt (accept -> COMPLETED) oder lehnt ab (reject -> REJECTED,
    oder READY bei rework). Erfordert TASK_REVIEW im Space; keine Selbst-Review. Idempotent."""
    principal_id = pid(principal_id)
    task = _row(conn, task_id)
    if not task:
        raise NotFound(task_id)
    space = _space_key(conn, task["space_id"])
    cap.require(conn, principal_id, cap.TASK_REVIEW, space)
    _no_self_gate(conn, task, principal_id)
    decision = str(decision).lower()
    if decision not in ("accept", "reject"):
        raise InvalidState("decision muss accept|reject sein")
    # Idempotenz
    if decision == "accept" and task["status"] == m.COMPLETED \
            and task["reviewed_by"] == str(principal_id):
        return get_task(conn, task_id)
    if decision == "reject" and task["status"] in (m.REJECTED, m.READY) \
            and task["reviewed_by"] == str(principal_id):
        return get_task(conn, task_id)
    if task["status"] != m.AWAITING_REVIEW:
        raise InvalidState("Task nicht im Review-Gate (Status %s)" % task["status"])
    now = now_iso()
    if decision == "accept":
        conn.execute("UPDATE tasks SET status='COMPLETED', completed_at=?, reviewed_by=?, "
                     "reviewed_at=?, review_note=?, updated_at=? WHERE task_id=?",
                     (now, str(principal_id), now, note, now, task_id))
        audit.log(conn, principal_id, "task_reviewed", "task", task_id, task["space_id"],
                  {"decision": "accept"})
        _refresh_dependents(conn, principal_id, task_id)
    else:
        new = m.READY if rework else m.REJECTED
        conn.execute("UPDATE tasks SET status=?, reviewed_by=?, reviewed_at=?, review_note=?, "
                     "updated_at=? WHERE task_id=?",
                     (new, str(principal_id), now, note, now, task_id))
        audit.log(conn, principal_id, "task_review_rejected", "task", task_id,
                  task["space_id"], {"to": new})
        if new == m.REJECTED:
            _refresh_dependents(conn, principal_id, task_id)
    conn.commit()
    return get_task(conn, task_id)


def approve_task(conn, principal_id, task_id, note=None):
    """Approver gibt das Approval-Gate frei -> APPROVED. Erfordert TASK_APPROVE im Space;
    keine Selbstfreigabe (ausser ADMIN). Idempotent. Post-Approval-Ausfuehrung = O2."""
    principal_id = pid(principal_id)
    task = _row(conn, task_id)
    if not task:
        raise NotFound(task_id)
    space = _space_key(conn, task["space_id"])
    cap.require(conn, principal_id, cap.TASK_APPROVE, space)
    _no_self_gate(conn, task, principal_id)
    if task["status"] == m.APPROVED and task["approved_by"] == str(principal_id):
        return get_task(conn, task_id)
    if task["status"] != m.AWAITING_APPROVAL:
        raise InvalidState("Task nicht im Approval-Gate (Status %s)" % task["status"])
    now = now_iso()
    conn.execute("UPDATE tasks SET status='APPROVED', approved_by=?, approved_at=?, "
                 "approval_note=?, updated_at=? WHERE task_id=?",
                 (str(principal_id), now, note, now, task_id))
    audit.log(conn, principal_id, "task_approved", "task", task_id, task["space_id"])
    conn.commit()
    return get_task(conn, task_id)


def reject_task(conn, principal_id, task_id, note=None):
    """Approver lehnt das Approval-Gate ab -> REJECTED. Erfordert TASK_APPROVE; keine
    Selbstfreigabe (ausser ADMIN). Idempotent."""
    principal_id = pid(principal_id)
    task = _row(conn, task_id)
    if not task:
        raise NotFound(task_id)
    space = _space_key(conn, task["space_id"])
    cap.require(conn, principal_id, cap.TASK_APPROVE, space)
    _no_self_gate(conn, task, principal_id)
    if task["status"] == m.REJECTED and task["approved_by"] == str(principal_id):
        return get_task(conn, task_id)
    if task["status"] != m.AWAITING_APPROVAL:
        raise InvalidState("Task nicht im Approval-Gate (Status %s)" % task["status"])
    now = now_iso()
    conn.execute("UPDATE tasks SET status='REJECTED', approved_by=?, approved_at=?, "
                 "approval_note=?, updated_at=? WHERE task_id=?",
                 (str(principal_id), now, note, now, task_id))
    audit.log(conn, principal_id, "task_approval_rejected", "task", task_id, task["space_id"])
    _refresh_dependents(conn, principal_id, task_id)
    conn.commit()
    return get_task(conn, task_id)


def _space_key(conn, space_id):
    r = acl.get_space_row(conn, space_id)
    return r["key"] if r else None


# ---------------------------------------------------------------- Runnable-Task-Auswahl
def list_runnable_tasks_for_agent(conn, principal_id, limit=200):
    """Grundlage fuer spaetere autonome Worker (O2). Filtert:
    status READY, Dependencies erfuellt, Space-ACL (claim), required_capabilities,
    aktiver Principal, preferred_agent (falls gesetzt). KEIN Auto-Claim hier."""
    principal_id = pid(principal_id)
    p = acl.get_principal(conn, principal_id)
    if not p or not p["active"]:
        return []
    out = []
    for t in list_tasks(conn, status=m.READY, limit=1000):
        space = _space_key(conn, _row(conn, t["task_id"])["space_id"])
        if not cap.check(conn, principal_id, cap.TASK_CLAIM, space):
            continue
        if deps_state(conn, t) != "satisfied":
            continue
        pref = t.get("preferred_agent")
        if pref and str(pref) != str(principal_id):
            continue
        need = t.get("required_capabilities") or []
        if any(not cap.check(conn, principal_id, c, space) for c in need):
            continue
        out.append(t)
        if len(out) >= limit:
            break
    return out


def fail_task(conn, principal_id, task_id, claim_token, reason=""):
    """Idempotentes Fail. Bereits FAILED mit gleichem Token -> No-op (kein weiterer
    retry_count++). Stale/fremdes Token -> StaleToken."""
    principal_id = pid(principal_id)
    task = _row(conn, task_id)
    if not task:
        raise NotFound(task_id)
    acl.require(conn, principal_id, task["space_id"], m.CAP_COMPLETE)
    if task["status"] == m.FAILED:
        if task["claim_token"] == claim_token:
            return get_task(conn, task_id)      # idempotent
        raise StaleToken("bereits mit anderem Claim fehlgeschlagen")
    now = now_iso()
    cur = conn.execute(
        "UPDATE tasks SET status='FAILED', failure_reason=?, retry_count=retry_count+1, "
        "lease_until=NULL, updated_at=? "
        "WHERE task_id=? AND claimed_by=? AND claim_token=? "
        "AND status IN ('CLAIMED','IN_PROGRESS')",
        (str(reason)[:500], now, task_id, str(principal_id), claim_token),
    )
    if cur.rowcount != 1:
        conn.rollback()
        raise StaleToken("fail abgelehnt (stale/kein aktiver Claim) fuer %s" % task_id)
    audit.log(conn, principal_id, "task_failed", "task", task_id, task["space_id"],
              {"reason": str(reason)[:200]})
    _refresh_dependents(conn, principal_id, task_id)
    conn.commit()
    return get_task(conn, task_id)
