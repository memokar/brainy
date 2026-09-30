"""Brainy Orchestration/Governance Tests (Phase O1). Temp-DB, KEIN produktiver Zugriff.
Aufruf: python3 tests/test_orchestration.py"""
import json
import os
import subprocess
import sys
import tempfile
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from brainy import (acl, db, models as m, orchestration as orch, service, spaces,  # noqa: E402
                    tasks, tokens, web)
from brainy.errors import ClaimConflict, InvalidState, PermissionDenied  # noqa: E402

_ok = [0]; _fail = [0]
SECRET = b"orch-test-session-secret-0123456789ABCDEF"


def check(label, cond, msg=""):
    if cond:
        _ok[0] += 1; print("PASS " + label)
    else:
        _fail[0] += 1; print("FAIL " + label + (": " + msg if msg else ""))


def raises(exc, fn, *a, **k):
    try:
        fn(*a, **k); return False
    except exc:
        return True
    except Exception:
        return False


def sh(root, *a):
    return subprocess.run(["git", "-C", root, *a], capture_output=True, text=True).stdout


def mini_kb():
    tmp = tempfile.mkdtemp(prefix="brainy_orchkb_"); k = os.path.join(tmp, "kb"); os.makedirs(k)
    for d in ("projects", "tools", "systems", "shared"):
        os.makedirs(os.path.join(k, d))
    open(os.path.join(k, "systems", "brainy.md"), "w").write("# Brainy\n")
    sh(k, "init", "-q", "-b", "main"); sh(k, "config", "user.name", "kb")
    sh(k, "config", "user.email", "kb@localhost"); sh(k, "add", "-A"); sh(k, "commit", "-q", "-m", "init")
    return k


def setup():
    tmp = tempfile.mkdtemp(prefix="brainy_orch_"); dbp = os.path.join(tmp, "brainy.db")
    conn = db.init_db(dbp)
    admin = acl.create_principal(conn, "USER", "admin", m.ADMIN)
    for kk in ("shared", "tools", "secret"):
        spaces.create_space(conn, admin["id"], kk, kk)
    agent = acl.create_principal(conn, "AGENT", "agent", m.AGENT)
    agent2 = acl.create_principal(conn, "AGENT", "agent2", m.AGENT)
    editor = acl.create_principal(conn, "USER", "editor", m.EDITOR)
    reader = acl.create_principal(conn, "USER", "reader", m.READER)
    acl.grant_permission(conn, admin["id"], "shared", agent["id"], can_read=1,
                         can_create_tasks=1, can_claim_tasks=1, can_complete_tasks=1, can_write=1)
    acl.grant_permission(conn, admin["id"], "shared", agent2["id"], can_read=1,
                         can_create_tasks=1, can_claim_tasks=1, can_complete_tasks=1)
    acl.grant_permission(conn, admin["id"], "shared", editor["id"], can_read=1,
                         can_create_tasks=1, can_claim_tasks=1, can_complete_tasks=1,
                         can_review=1, can_approve=1)
    acl.grant_permission(conn, admin["id"], "shared", reader["id"], can_read=1)
    acl.grant_permission(conn, admin["id"], "tools", agent["id"], can_read=1,
                         can_create_tasks=1, can_claim_tasks=1, can_complete_tasks=1)
    tok = {"agent": tokens.create_service_token(conn, agent["id"])["token"],
           "editor": tokens.create_service_token(conn, editor["id"])["token"]}
    ids = {"admin": admin["id"], "agent": agent["id"], "agent2": agent2["id"],
           "editor": editor["id"], "reader": reader["id"]}
    conn.close()
    svc = service.BrainyService(dbp, mini_kb(), rate_limit="100000/60")
    return svc, dbp, ids, tok


svc, dbp, ID, TOK = setup()


def conn():
    return db.connect(dbp)


def mk(c, **kw):
    kw.setdefault("status", m.READY)
    return tasks.create_task(c, ID.get(kw.pop("as_", "agent")), "shared", kw.pop("title", "t"), **kw)


# ============ Policy (A–G) ============
check("A default -> REVIEW", orch.evaluate_policy("REVIEW", None, None)["effective"] == "REVIEW")
check("B INTERNAL_READ+LOW+AUTO -> AUTO",
      orch.evaluate_policy("AUTO", "LOW", "INTERNAL_READ")["effective"] == "AUTO")
check("C RESEARCH+LOW+AUTO -> AUTO",
      orch.evaluate_policy("AUTO", "LOW", "RESEARCH")["effective"] == "AUTO")
pol_d = orch.evaluate_policy("AUTO", "MEDIUM", "PUBLISH")
check("D PUBLISH+AUTO -> APPROVAL (escalated)",
      pol_d["effective"] == "APPROVAL" and pol_d["escalated"] and pol_d["approval_required"])
check("E DEPLOY+AUTO -> APPROVAL",
      orch.evaluate_policy("AUTO", "LOW", "DEPLOY")["effective"] == "APPROVAL")
check("F PAYMENT+AUTO -> APPROVAL",
      orch.evaluate_policy("AUTO", "LOW", "PAYMENT")["effective"] == "APPROVAL")
check("G CRITICAL -> APPROVAL",
      orch.evaluate_policy("AUTO", "CRITICAL", "INTERNAL_READ")["effective"] == "APPROVAL")
check("Default-Policy: unbekannte action_class -> REVIEW (nie AUTO)",
      orch.evaluate_policy("AUTO", "LOW", "FOO_UNKNOWN")["effective"] != "AUTO")
check("Default-Policy: unbekanntes risk -> nicht AUTO",
      orch.evaluate_policy("AUTO", "WEIRD", "INTERNAL_READ")["effective"] != "AUTO")

# create_task speichert effective
c = conn()
td = mk(c, title="pub", execution_mode="AUTO", risk_level="MEDIUM", action_class="PUBLISH")
check("create_task speichert effective=APPROVAL + approval_required",
      td["effective_execution_mode"] == "APPROVAL" and td["approval_required"] == 1
      and td["execution_mode"] == "AUTO")
c.close()

# ============ Engine (H–R) ============
def claim_complete(c, tid, who="agent", result="done"):
    cl = tasks.claim_task(c, ID[who], tid)
    return tasks.complete_task(c, ID[who], tid, cl["claim_token"], result=result)

# H AUTO complete -> COMPLETED
c = conn()
ta = mk(c, title="auto", execution_mode="AUTO", risk_level="LOW", action_class="INTERNAL_READ")
r = claim_complete(c, ta["task_id"])
check("H AUTO complete -> COMPLETED", r["status"] == "COMPLETED")

# I REVIEW complete -> AWAITING_REVIEW
tr = mk(c, title="rev", execution_mode="REVIEW", risk_level="MEDIUM", action_class="CODE_CHANGE")
r = claim_complete(c, tr["task_id"])
check("I REVIEW complete -> AWAITING_REVIEW", r["status"] == "AWAITING_REVIEW")

# J AGENT kann sich nicht selbst reviewen (kein Recht)
check("J Agent kann nicht reviewen (PermissionDenied)",
      raises(PermissionDenied, tasks.review_task, c, ID["agent"], tr["task_id"], "accept"))

# K Reviewer accept -> COMPLETED
r = tasks.review_task(c, ID["editor"], tr["task_id"], "accept", note="ok")
check("K Reviewer accept -> COMPLETED + reviewed_by",
      r["status"] == "COMPLETED" and r["reviewed_by"] == str(ID["editor"]))

# L Reviewer reject -> REJECTED
tr2 = mk(c, title="rev2", execution_mode="REVIEW")
claim_complete(c, tr2["task_id"])
r = tasks.review_task(c, ID["editor"], tr2["task_id"], "reject", note="nope")
check("L Reviewer reject -> REJECTED", r["status"] == "REJECTED")

# M APPROVAL gate blockiert kritischen Abschluss
tp = mk(c, title="pub2", execution_mode="AUTO", action_class="PUBLISH")
r = claim_complete(c, tp["task_id"])
check("M APPROVAL: complete -> AWAITING_APPROVAL (NICHT COMPLETED)",
      r["status"] == "AWAITING_APPROVAL")

# N Approver approve -> APPROVED
r = tasks.approve_task(c, ID["editor"], tp["task_id"], note="go")
check("N Approver approve -> APPROVED + approved_by",
      r["status"] == "APPROVED" and r["approved_by"] == str(ID["editor"]))

# O Agent kann sich nicht selbst approven; + Selbst-Approval-Gate (editor als Owner)
tp2 = mk(c, title="pub3", action_class="DEPLOY")
claim_complete(c, tp2["task_id"])
check("O Agent kann nicht approven (kein Recht)",
      raises(PermissionDenied, tasks.approve_task, c, ID["agent"], tp2["task_id"]))
# editor arbeitet selbst -> darf sich nicht selbst approven
tp3 = mk(c, title="pub4", as_="editor", action_class="DEPLOY")
claim_complete(c, tp3["task_id"], who="editor")
check("O2 Selbstfreigabe blockiert (editor Owner, non-admin)",
      raises(PermissionDenied, tasks.approve_task, c, ID["editor"], tp3["task_id"]))

# P Approval reject
tp4 = mk(c, title="pub5", action_class="PUBLISH")
claim_complete(c, tp4["task_id"])
r = tasks.reject_task(c, ID["editor"], tp4["task_id"], note="no")
check("P Approval reject -> REJECTED", r["status"] == "REJECTED")

# Q approve idempotent
tp5 = mk(c, title="pub6", action_class="PUBLISH")
claim_complete(c, tp5["task_id"])
tasks.approve_task(c, ID["editor"], tp5["task_id"])
r2 = tasks.approve_task(c, ID["editor"], tp5["task_id"])
check("Q approve idempotent (2x -> APPROVED, kein Fehler)", r2["status"] == "APPROVED")

# R konkurrierendes approve/reject sauber (nach approve -> reject unzulaessig)
check("R kein widerspruechliches Reject nach Approve",
      raises(InvalidState, tasks.reject_task, c, ID["editor"], tp5["task_id"]))
c.close()

# ============ Dependencies (S–U) ============
c = conn()
A = mk(c, title="A", execution_mode="AUTO", action_class="INTERNAL_READ")
B = mk(c, title="B", execution_mode="AUTO", action_class="INTERNAL_READ",
       dependencies=[A["task_id"]])
check("S dependency verhindert Claim von B",
      raises(ClaimConflict, tasks.claim_task, c, ID["agent"], B["task_id"]))
claim_complete(c, A["task_id"])   # A -> COMPLETED
runnable = [t["task_id"] for t in tasks.list_runnable_tasks_for_agent(c, ID["agent"])]
check("T dependency completed -> B runnable + claimbar",
      B["task_id"] in runnable and tasks.claim_task(c, ID["agent"], B["task_id"])["claim_token"])

# U failed dependency -> BLOCKED
A2 = mk(c, title="A2", execution_mode="AUTO", action_class="INTERNAL_READ")
B2 = mk(c, title="B2", execution_mode="AUTO", action_class="INTERNAL_READ",
        dependencies=[A2["task_id"]])
cl = tasks.claim_task(c, ID["agent"], A2["task_id"])
tasks.fail_task(c, ID["agent"], A2["task_id"], cl["claim_token"], reason="x")
check("U failed dependency -> B2 BLOCKED",
      tasks.get_task(c, B2["task_id"])["status"] == "BLOCKED")
# Release-Pfad: A2 wieder aufmachen + abschliessen -> B2 BLOCKED -> READY (dependency_released)
tasks.set_status(c, ID["admin"], A2["task_id"], m.READY)
claim_complete(c, A2["task_id"])
check("dependency_released: B2 BLOCKED -> READY nach A2 COMPLETED",
      tasks.get_task(c, B2["task_id"])["status"] == "READY")
c.close()

# ============ Runnable-Filter (V–X) ============
c = conn()
# V ACL: READY task in 'secret' (agent hat keine ACL) -> nicht runnable
sec = tasks.create_task(c, ID["admin"], "secret", "sec", status=m.READY,
                        execution_mode="AUTO", action_class="INTERNAL_READ")
rid = [t["task_id"] for t in tasks.list_runnable_tasks_for_agent(c, ID["agent"])]
check("V list_runnable filtert ACL (secret nicht sichtbar)", sec["task_id"] not in rid)

# W required_capabilities: knowledge.write -> nur agent (hat write), nicht agent2
wt = mk(c, title="needwrite", execution_mode="AUTO", action_class="INTERNAL_READ",
        required_capabilities=["knowledge.write"])
r_agent = [t["task_id"] for t in tasks.list_runnable_tasks_for_agent(c, ID["agent"])]
r_ag2 = [t["task_id"] for t in tasks.list_runnable_tasks_for_agent(c, ID["agent2"])]
check("W required_capabilities filtert (agent hat write, agent2 nicht)",
      wt["task_id"] in r_agent and wt["task_id"] not in r_ag2)

# X preferred_agent
pt = mk(c, title="pref", execution_mode="AUTO", action_class="INTERNAL_READ",
        preferred_agent="agent2")
r_agent = [t["task_id"] for t in tasks.list_runnable_tasks_for_agent(c, ID["agent"])]
r_ag2 = [t["task_id"] for t in tasks.list_runnable_tasks_for_agent(c, ID["agent2"])]
check("X preferred_agent: nur agent2 sieht Task",
      pt["task_id"] in r_ag2 and pt["task_id"] not in r_agent)
c.close()

# ============ MCP Tool-Visibility (Y) ============
def tools_for(token):
    st, ct, body = svc.handle_mcp("POST", "Bearer " + token, json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode())
    return {t["name"] for t in json.loads(body)["result"]["tools"]}

editor_tools = tools_for(TOK["editor"])
agent_tools = tools_for(TOK["agent"])
check("Y editor sieht review_task/approve_task/reject_task",
      {"review_task", "approve_task", "reject_task"} <= editor_tools)
check("Y agent sieht KEINE Governance-Tools, aber list_runnable_tasks",
      "review_task" not in agent_tools and "approve_task" not in agent_tools
      and "list_runnable_tasks" in agent_tools)

# ============ Web (Z, AA) ============
app = web.BrainyWeb(svc, SECRET)


def ck(pid):
    return "%s=%s" % (web.COOKIE, web.make_session(SECRET, pid))


def csrf(pid):
    return web.csrf_token(SECRET, web.make_session(SECRET, pid))


c = conn()
zt = mk(c, title="webrev", execution_mode="REVIEW")
claim_complete(c, zt["task_id"])
c.close()
r_ed = app.handle("GET", "/admin/tasks/view", "id=" + zt["task_id"], ck(ID["editor"]), b"")
r_ag = app.handle("GET", "/admin/tasks/view", "id=" + zt["task_id"], ck(ID["agent"]), b"")
check("Z Web-Buttons: editor sieht 'Review & Accept'",
      r_ed[0] == 200 and "Review &amp; Accept" in r_ed[3].decode())
check("Z Web-Buttons: agent sieht KEINE Review-Buttons",
      r_ag[0] == 200 and "Review &amp; Accept" not in r_ag[3].decode())
# AA CSRF: govern ohne Token -> 403
r_nocsrf = app.handle("POST", "/admin/tasks/govern", "",
                      ck(ID["editor"]), urllib.parse.urlencode(
                          {"id": zt["task_id"], "action": "review_accept"}).encode())
check("AA CSRF: govern ohne Token -> 403", r_nocsrf[0] == 403)
# mit CSRF -> akzeptiert (redirect)
r_ok = app.handle("POST", "/admin/tasks/govern", "",
                  ck(ID["editor"]), urllib.parse.urlencode(
                      {"id": zt["task_id"], "action": "review_accept",
                       "csrf": csrf(ID["editor"])}).encode())
check("AA govern mit CSRF -> 303 + COMPLETED",
      r_ok[0] == 303 and tasks.get_task(conn(), zt["task_id"])["status"] == "COMPLETED")

# ============ Audit (AB) ============
c = conn()
acts = {r["action"] for r in c.execute("SELECT action FROM audit_events").fetchall()}
need = {"task_policy_evaluated", "task_policy_escalated", "task_awaiting_review",
        "task_reviewed", "task_review_rejected", "task_awaiting_approval", "task_approved",
        "task_approval_rejected", "dependency_blocked", "dependency_released"}
missing = need - acts
check("AB Audit-Events vollstaendig", not missing, "fehlt: %s" % missing)
c.close()

print("\nGESAMT: %d PASS, %d FAIL" % (_ok[0], _fail[0]))
sys.exit(0 if _fail[0] == 0 else 1)
