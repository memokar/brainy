"""Brainy Phase-C Auth/Roles/Spaces Tests (A-X). Nur Temp-DB/Test-Repos.
KEINE produktiven Tokens/User. Aufruf: python3 tests/test_auth.py"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from brainy import (acl, audit, auth, capabilities as cap, db, knowledge,       # noqa: E402
                    models as m, spaces, tasks, tokens)
from brainy.errors import (AuthFailed, BrainyError, PermissionDenied)           # noqa: E402

PAST = "2000-01-01T00:00:00+00:00"
_ok = [0]
_fail = [0]


def check(label, cond, msg=""):
    if cond:
        _ok[0] += 1; print("PASS " + label)
    else:
        _fail[0] += 1; print("FAIL " + label + (": " + msg if msg else ""))


def raises(excs, fn, *a, **k):
    try:
        fn(*a, **k); return False
    except excs:
        return True
    except Exception:
        return False


def sh(root, *args):
    return subprocess.run(["git", "-C", root, *args], capture_output=True, text=True).stdout


def new_db():
    return db.init_db(os.path.join(tempfile.mkdtemp(prefix="brainy_c_"), "brainy.db"))


def fresh():
    conn = new_db()
    admin = acl.create_principal(conn, "USER", "admin", m.ADMIN)
    for k in ("spaceA", "spaceB", "tools"):
        spaces.create_space(conn, admin["id"], k, k)
    editor = acl.create_principal(conn, "USER", "editor", m.EDITOR)
    agent = acl.create_principal(conn, "AGENT", "agent1", m.AGENT)
    reader = acl.create_principal(conn, "USER", "reader", m.READER)
    acl.grant_permission(conn, admin["id"], "spaceA", editor["id"],
                         can_read=1, can_write=1, can_create_tasks=1, can_claim_tasks=1,
                         can_complete_tasks=1)
    acl.grant_permission(conn, admin["id"], "spaceA", agent["id"],
                         can_read=1, can_create_tasks=1, can_claim_tasks=1, can_complete_tasks=1)
    acl.grant_permission(conn, admin["id"], "spaceA", reader["id"], can_read=1)
    acl.grant_permission(conn, admin["id"], "tools", reader["id"], can_read=1)
    return conn, dict(admin=admin, editor=editor, agent=agent, reader=reader)


def mini_kb():
    tmp = tempfile.mkdtemp(prefix="brainy_ckb_")
    kroot = os.path.join(tmp, "kb"); os.makedirs(kroot)
    for d in ("projects", "tools", "systems", "shared"):
        os.makedirs(os.path.join(kroot, d))
    with open(os.path.join(kroot, "tools", "demo-bot.md"), "w", encoding="utf-8") as fh:
        fh.write("# Demo-Bot\n\nText.\n")
    sh(kroot, "init", "-q", "-b", "main")
    sh(kroot, "config", "user.name", "kb"); sh(kroot, "config", "user.email", "kb@localhost")
    sh(kroot, "add", "-A"); sh(kroot, "commit", "-q", "-m", "init")
    return kroot


# A: Principal anlegen
conn, P = fresh()
check("A Principal anlegen", P["admin"]["id"] and P["admin"]["role"] == m.ADMIN)

# B: Duplicate / invalid abgelehnt
check("B1 Duplicate abgelehnt",
      raises(BrainyError, acl.create_principal, conn, "USER", "admin", m.ADMIN))
check("B2 invalid role abgelehnt",
      raises(BrainyError, acl.create_principal, conn, "USER", "x1", "BOSS"))
check("B3 invalid type abgelehnt",
      raises(BrainyError, acl.create_principal, conn, "ALIEN", "x2", m.READER))

# C: deaktivierter Principal -> Auth abgelehnt
tk = tokens.create_service_token(conn, P["agent"]["id"])
acl.disable_principal(conn, "admin", P["agent"]["id"])
check("C deaktivierter Principal Auth abgelehnt",
      raises(AuthFailed, tokens.authenticate_service_token, conn, tk["token"]))

# D/E/F/G: Token erstellen / nur Hash / Auth / falsch
conn, P = fresh()
tk = tokens.create_service_token(conn, P["agent"]["id"], description="test")
check("D Service-Token erstellt", tk["token"] and tk["token_id"] in tk["token"])
secret = tk["token"].split(".", 1)[1]
row = dict(conn.execute("SELECT * FROM service_tokens WHERE token_id=?",
                        (tk["token_id"],)).fetchone())
check("E DB nur Hash, kein Klartext",
      row["token_hash"] != secret and len(row["token_hash"]) == 64
      and secret not in " ".join(str(v) for v in row.values()))
pid_auth, tid_auth = tokens.authenticate_service_token(conn, tk["token"])
check("F gueltiger Token authentifiziert", pid_auth == P["agent"]["id"])
check("G falscher Token abgelehnt",
      raises(AuthFailed, tokens.authenticate_service_token, conn, tk["token_id"] + ".WRONG"))

# H: abgelaufen
tk_exp = tokens.create_service_token(conn, P["agent"]["id"], expires_at=PAST)
check("H abgelaufener Token abgelehnt",
      raises(AuthFailed, tokens.authenticate_service_token, conn, tk_exp["token"]))

# I: revoked
tk_rev = tokens.create_service_token(conn, P["agent"]["id"])
tokens.revoke_service_token(conn, tk_rev["token_id"])
check("I revoked Token abgelehnt",
      raises(AuthFailed, tokens.authenticate_service_token, conn, tk_rev["token"]))

# J: Rotation
tk_old = tokens.create_service_token(conn, P["agent"]["id"])
tk_new = tokens.rotate_service_token(conn, tk_old["token_id"])
old_dead = raises(AuthFailed, tokens.authenticate_service_token, conn, tk_old["token"])
new_ok = tokens.authenticate_service_token(conn, tk_new["token"])[0] == P["agent"]["id"]
check("J Rotation invalidiert alten Token, neuer gueltig", old_dead and new_ok)

# K: list_service_tokens ohne Hash/Secret
lst = tokens.list_service_tokens(conn, P["agent"]["id"])
check("K list_service_tokens ohne Hash/Secret",
      lst and all("token_hash" not in t and "token" not in t for t in lst))

# L: READER matrix
check("L READER matrix",
      cap.check(conn, P["reader"]["id"], cap.KNOWLEDGE_READ, "spaceA") is True and
      cap.check(conn, P["reader"]["id"], cap.KNOWLEDGE_WRITE, "spaceA") is False and
      cap.check(conn, P["reader"]["id"], cap.TASK_CREATE, "spaceA") is False)

# M: AGENT matrix (write nur mit ACL)
before = cap.check(conn, P["agent"]["id"], cap.KNOWLEDGE_WRITE, "spaceA")
acl.grant_permission(conn, P["admin"]["id"], "spaceA", P["agent"]["id"],
                     can_read=1, can_write=1, can_create_tasks=1, can_claim_tasks=1,
                     can_complete_tasks=1)
after = cap.check(conn, P["agent"]["id"], cap.KNOWLEDGE_WRITE, "spaceA")
check("M AGENT matrix (read/create/claim/complete ja; write nur mit ACL; principal.manage nein)",
      cap.check(conn, P["agent"]["id"], cap.TASK_CREATE, "spaceA") and
      cap.check(conn, P["agent"]["id"], cap.TASK_CLAIM, "spaceA") and
      cap.check(conn, P["agent"]["id"], cap.TASK_COMPLETE, "spaceA") and
      before is False and after is True and
      cap.check(conn, P["agent"]["id"], cap.PRINCIPAL_MANAGE) is False)

# N: EDITOR matrix
check("N EDITOR matrix",
      cap.check(conn, P["editor"]["id"], cap.KNOWLEDGE_WRITE, "spaceA") is True and
      cap.check(conn, P["editor"]["id"], cap.TASK_CREATE, "spaceA") is True and
      cap.check(conn, P["editor"]["id"], cap.TOKEN_MANAGE) is False and
      cap.check(conn, P["editor"]["id"], cap.AUDIT_READ) is True)

# O: ADMIN matrix (auch ohne Space-ACL)
check("O ADMIN matrix (alles, auch ohne ACL)",
      cap.check(conn, P["admin"]["id"], cap.KNOWLEDGE_WRITE, "spaceB") is True and
      cap.check(conn, P["admin"]["id"], cap.PRINCIPAL_MANAGE) is True and
      cap.check(conn, P["admin"]["id"], cap.SPACE_MANAGE, "spaceB") is True)

# P: Space-Isolation A/B
check("P AGENT Space A ja / Space B nein",
      cap.check(conn, P["agent"]["id"], cap.TASK_CLAIM, "spaceA") is True and
      cap.check(conn, P["agent"]["id"], cap.TASK_CLAIM, "spaceB") is False)

# Q: deaktivierter Space blockiert
acl.grant_permission(conn, P["admin"]["id"], "spaceB", P["reader"]["id"], can_read=1)
conn.execute("UPDATE spaces SET active=0 WHERE key='spaceB'"); conn.commit()
check("Q deaktivierter Space blockiert normalen Zugriff",
      cap.check(conn, P["reader"]["id"], cap.KNOWLEDGE_READ, "spaceB") is False)

# R: ACL-Aenderungen Audit
acts = {e["action"] for e in audit.list_events(conn, limit=300)}
acl.remove_acl(conn, P["admin"]["id"], "spaceA", P["reader"]["id"])
acts2 = {e["action"] for e in audit.list_events(conn, limit=300)}
check("R ACL-Aenderungen auditiert",
      {"acl_granted"} <= acts and "acl_removed" in acts2)

# S: Token-Events Audit OHNE Secret
conn, P = fresh()
tk = tokens.create_service_token(conn, P["agent"]["id"])
tokens.authenticate_service_token(conn, tk["token"])
raises(AuthFailed, tokens.authenticate_service_token, conn, tk["token_id"] + ".WRONG")
tokens.revoke_service_token(conn, tk["token_id"])
sec = tk["token"].split(".", 1)[1]
allrows = conn.execute("SELECT actor, action, object_id, metadata FROM audit_events").fetchall()
leak = any(sec in " ".join(str(x) for x in r) for r in allrows)
tokacts = {r["action"] for r in allrows}
check("S Token-Events auditiert OHNE Secret",
      {"token_created", "auth_success", "auth_failed", "token_revoked"} <= tokacts and not leak)

# T: Bootstrap nur bei leerem Store
empty = new_db()
bs = auth.bootstrap_admin(empty, name="root-admin")
check("T Bootstrap bei leerem Store ok + nur-bei-leer",
      bs["principal_id"] and raises(BrainyError, auth.bootstrap_admin, empty))

# U: Bootstrap ohne Default-Secret
empty2 = new_db()
bs2 = auth.bootstrap_admin(empty2, with_token=False)
ntok = empty2.execute("SELECT COUNT(*) c FROM service_tokens").fetchone()["c"]
check("U Bootstrap erzeugt kein Default-Secret", bs2["token"] is None and ntok == 0)

# V: Knowledge-Service respektiert AuthContext
conn, P = fresh()
kroot = mini_kb()
ctx_reader = auth.context_for_principal(conn, P["reader"]["id"])
doc = knowledge.get_document(conn, ctx_reader, "tools/demo-bot.md", root=kroot)
noacc = acl.create_principal(conn, "USER", "noacc", m.READER)
ctx_noacc = auth.context_for_principal(conn, noacc["id"])
check("V Knowledge respektiert AuthContext (erlaubt/verweigert)",
      "Demo-Bot" in doc["content"] and
      raises(PermissionDenied, knowledge.get_document, conn, ctx_noacc,
             "tools/demo-bot.md", root=kroot))

# W: Task-Service respektiert AuthContext
t = tasks.create_task(conn, P["agent"]["id"], "spaceA", "T", type="ops", execution_mode="AUTO", action_class="INTERNAL_READ")
tasks.set_status(conn, P["agent"]["id"], t["task_id"], m.READY)
ctx_agent = auth.context_for_principal(conn, P["agent"]["id"])
c = tasks.claim_task(conn, ctx_agent, t["task_id"])
tk_task = tasks.get_task(conn, t["task_id"])
check("W Task respektiert AuthContext (claimed_by = int id, nicht ctx)",
      bool(c["claim_token"]) and tk_task["claimed_by"] == str(P["agent"]["id"]))

# X: Regression Phase A/B (Kurz-Lebenszyklus + Knowledge-Read mit int-ids)
tasks.complete_task(conn, P["agent"]["id"], t["task_id"], c["claim_token"], result="ok")
reg_ok = tasks.get_task(conn, t["task_id"])["status"] == m.COMPLETED
reg_read = "Demo-Bot" in knowledge.get_document(conn, P["reader"]["id"],
                                               "tools/demo-bot.md", root=kroot)["content"]
check("X Regression A/B (Task-Lifecycle + Knowledge-Read int-ids)", reg_ok and reg_read)

print("\nGESAMT: %d PASS, %d FAIL" % (_ok[0], _fail[0]))
sys.exit(0 if _fail[0] == 0 else 1)
