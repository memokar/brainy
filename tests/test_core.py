"""Brainy Core Phase-A Tests (A-O). Nur temporaere Test-DBs, keine Produktivdaten.
Aufruf: python3 tests/test_core.py"""
import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from brainy import acl, audit, db, models as m, spaces, tasks          # noqa: E402
from brainy.errors import ClaimConflict, PermissionDenied, StaleToken  # noqa: E402

PAST = "2000-01-01T00:00:00+00:00"

_ok = [0]
_fail = [0]


def check(label, cond, msg=""):
    if cond:
        _ok[0] += 1
        print("PASS " + label)
    else:
        _fail[0] += 1
        print("FAIL " + label + (": " + msg if msg else ""))


def raises(exc, fn, *a, **k):
    try:
        fn(*a, **k)
        return False
    except exc:
        return True
    except Exception:
        return False


def fresh():
    tmp = tempfile.mkdtemp(prefix="brainy_test_")
    path = os.path.join(tmp, "brainy.db")
    conn = db.init_db(path)
    admin = acl.create_principal(conn, "human", "admin", m.ADMIN)
    spaces.create_space(conn, admin["id"], "test", "Test")
    spaces.create_space(conn, admin["id"], "andere", "Andere")
    editor = acl.create_principal(conn, "human", "editor", m.EDITOR)
    agent = acl.create_principal(conn, "agent", "agent1", m.AGENT)
    agent2 = acl.create_principal(conn, "agent", "agent2", m.AGENT)
    reader = acl.create_principal(conn, "human", "reader", m.READER)
    full = dict(can_read=1, can_write=1, can_create_tasks=1, can_claim_tasks=1,
                can_complete_tasks=1)
    acl.set_space_acl(conn, admin["id"], "test", editor["id"], **full)
    acl.set_space_acl(conn, admin["id"], "test", agent["id"],
                      can_read=1, can_create_tasks=1, can_claim_tasks=1, can_complete_tasks=1)
    acl.set_space_acl(conn, admin["id"], "test", agent2["id"],
                      can_read=1, can_create_tasks=1, can_claim_tasks=1, can_complete_tasks=1)
    acl.set_space_acl(conn, admin["id"], "test", reader["id"], can_read=1)
    return path, conn, dict(admin=admin, editor=editor, agent=agent, agent2=agent2,
                            reader=reader)


def ready_task(conn, p):
    t = tasks.create_task(conn, p["id"], "test", "T", type="ops", execution_mode="AUTO", action_class="INTERNAL_READ")
    tasks.set_status(conn, p["id"], t["task_id"], m.READY)
    return t["task_id"]


# ---- A: create -> OPEN
path, conn, P = fresh()
t = tasks.create_task(conn, P["agent"]["id"], "test", "Task A", type="ops", execution_mode="AUTO", action_class="INTERNAL_READ")
check("A create->OPEN", t["status"] == m.OPEN, t["status"])

# ---- B: OPEN nicht claimbar
check("B OPEN nicht claimbar",
      raises(ClaimConflict, tasks.claim_task, conn, P["agent"]["id"], t["task_id"]))

# ---- C: READY claimbar
tasks.set_status(conn, P["agent"]["id"], t["task_id"], m.READY)
c = tasks.claim_task(conn, P["agent"]["id"], t["task_id"])
check("C READY claimbar", bool(c["claim_token"]) and
      tasks.get_task(conn, t["task_id"])["status"] == m.CLAIMED)

# ---- D: zwei parallele Claims -> genau einer gewinnt
path2, conn2, P2 = fresh()
tid = ready_task(conn2, P2["agent"])
res = {"ok": 0, "conflict": 0}
lock = threading.Lock()


def worker(pid):
    c = db.connect(path2)
    try:
        tasks.claim_task(c, pid, tid)
        with lock:
            res["ok"] += 1
    except ClaimConflict:
        with lock:
            res["conflict"] += 1
    except Exception:
        pass
    finally:
        c.close()


th = [threading.Thread(target=worker, args=(P2["agent"]["id"],)),
      threading.Thread(target=worker, args=(P2["agent2"]["id"],))]
[x.start() for x in th]
[x.join() for x in th]
check("D parallel claim: genau 1 gewinnt", res["ok"] == 1 and res["conflict"] == 1,
      str(res))

# ---- E: renew
path, conn, P = fresh()
tid = ready_task(conn, P["agent"])
c = tasks.claim_task(conn, P["agent"]["id"], tid)
r = tasks.renew_claim(conn, P["agent"]["id"], tid, c["claim_token"])
check("E renew ok", r["lease_until"] >= c["lease_until"])

# ---- F: falscher Token abgelehnt
check("F falscher Token abgelehnt",
      raises(StaleToken, tasks.renew_claim, conn, P["agent"]["id"], tid, "falsch") and
      raises(StaleToken, tasks.complete_task, conn, P["agent"]["id"], tid, "falsch"))

# ---- G: abgelaufener Claim neu claimbar
conn.execute("UPDATE tasks SET lease_until=? WHERE task_id=?", (PAST, tid))
conn.commit()
c2 = tasks.claim_task(conn, P["agent2"]["id"], tid)
check("G expired -> reclaim", c2["claim_token"] != c["claim_token"] and
      tasks.get_task(conn, tid)["claimed_by"] == str(P["agent2"]["id"]))

# ---- H: alter Token danach ungueltig
check("H alter Token ungueltig (complete/renew/release)",
      raises(StaleToken, tasks.complete_task, conn, P["agent"]["id"], tid, c["claim_token"]) and
      raises(StaleToken, tasks.renew_claim, conn, P["agent"]["id"], tid, c["claim_token"]) and
      raises(StaleToken, tasks.release_task, conn, P["agent"]["id"], tid, c["claim_token"]))

# ---- I: complete idempotent
path, conn, P = fresh()
tid = ready_task(conn, P["agent"])
c = tasks.claim_task(conn, P["agent"]["id"], tid)
tasks.complete_task(conn, P["agent"]["id"], tid, c["claim_token"], result="done")
tasks.complete_task(conn, P["agent"]["id"], tid, c["claim_token"], result="done")  # no-op
n_comp = len(audit.list_events(conn, object_id=tid, action="task_completed"))
check("I complete idempotent (1 Event, Status COMPLETED)",
      n_comp == 1 and tasks.get_task(conn, tid)["status"] == m.COMPLETED, "events=%d" % n_comp)

# ---- J: fail idempotent
path, conn, P = fresh()
tid = ready_task(conn, P["agent"])
c = tasks.claim_task(conn, P["agent"]["id"], tid)
tasks.fail_task(conn, P["agent"]["id"], tid, c["claim_token"], reason="x")
tasks.fail_task(conn, P["agent"]["id"], tid, c["claim_token"], reason="x")  # no-op
tk = tasks.get_task(conn, tid)
n_fail = len(audit.list_events(conn, object_id=tid, action="task_failed"))
check("J fail idempotent (1 Event, retry_count=1)",
      n_fail == 1 and tk["retry_count"] == 1 and tk["status"] == m.FAILED,
      "events=%d retry=%d" % (n_fail, tk["retry_count"]))

# ---- K: release
path, conn, P = fresh()
tid = ready_task(conn, P["agent"])
c = tasks.claim_task(conn, P["agent"]["id"], tid)
tasks.release_task(conn, P["agent"]["id"], tid, c["claim_token"])
tk = tasks.get_task(conn, tid)
check("K release -> READY, Claim geleert",
      tk["status"] == m.READY and tk["claimed_by"] is None and tk["claim_token"] is None)

# ---- L: ACL erlaubt/verweigert
path, conn, P = fresh()
check("L1 READER darf nicht erstellen",
      raises(PermissionDenied, tasks.create_task, conn, P["reader"]["id"], "test", "x"))
check("L2 READER darf lesen (check_permission)",
      acl.check_permission(conn, P["reader"]["id"], "test", m.CAP_READ) is True)
check("L3 AGENT claim nur in erlaubtem Space (test ja / andere nein)",
      acl.check_permission(conn, P["agent"]["id"], "test", m.CAP_CLAIM) is True and
      acl.check_permission(conn, P["agent"]["id"], "andere", m.CAP_CLAIM) is False)
tid = ready_task(conn, P["agent"])
check("L4 AGENT ohne Space-ACL kann dort nicht claimen (Space 'andere')",
      raises(PermissionDenied, tasks.create_task, conn, P["agent"]["id"], "andere", "x"))
check("L5 ADMIN global erlaubt",
      acl.check_permission(conn, P["admin"]["id"], "andere", m.CAP_MANAGE_SPACE) is True)

# ---- M: Audit-Events korrekt
path, conn, P = fresh()
tid = ready_task(conn, P["agent"])
c = tasks.claim_task(conn, P["agent"]["id"], tid)
acts = {e["action"] for e in audit.list_events(conn, object_id=tid)}
check("M Audit enthaelt created/ready/claimed",
      {"task_created", "task_ready", "task_claimed"}.issubset(acts), str(acts))

# ---- N: Foreign Keys aktiv
check("N foreign_keys aktiv", conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1)

# ---- O: WAL aktiv + Audit append-only
jm = conn.execute("PRAGMA journal_mode").fetchone()[0]
append_only = False
try:
    conn.execute("UPDATE audit_events SET action='x' WHERE id=1")
    conn.commit()
except Exception:
    conn.rollback()
    append_only = True
check("O WAL aktiv + Audit append-only", jm.lower() == "wal" and append_only,
      "journal=%s append_only=%s" % (jm, append_only))

print("\nGESAMT: %d PASS, %d FAIL" % (_ok[0], _fail[0]))
sys.exit(0 if _fail[0] == 0 else 1)
