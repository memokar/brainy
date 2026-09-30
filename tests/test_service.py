"""Brainy Phase-D MCP-Service Tests (A-T). Temp-DB/Test-Repo, KEIN Socket noetig
(svc.handle direkt), KEIN produktiver Write. Aufruf: python3 tests/test_service.py"""
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from brainy import (acl, audit, db, gitops, models as m, service, spaces,        # noqa: E402
                    tasks, tokens)
from brainy.errors import BrainyError                                            # noqa: E402

PAST = "2000-01-01T00:00:00+00:00"
_ok = [0]; _fail = [0]


def check(label, cond, msg=""):
    if cond:
        _ok[0] += 1; print("PASS " + label)
    else:
        _fail[0] += 1; print("FAIL " + label + (": " + msg if msg else ""))


def sh(root, *a):
    return subprocess.run(["git", "-C", root, *a], capture_output=True, text=True).stdout


def mini_kb():
    tmp = tempfile.mkdtemp(prefix="brainy_dkb_")
    k = os.path.join(tmp, "kb"); os.makedirs(k)
    for d in ("projects", "tools", "systems", "shared"):
        os.makedirs(os.path.join(k, d))
    open(os.path.join(k, "tools", "demo-bot.md"), "w").write("# Demo-Bot\n\nText.\n")
    open(os.path.join(k, "shared", "todo.md"), "w").write("# TODO\n")
    sh(k, "init", "-q", "-b", "main"); sh(k, "config", "user.name", "kb")
    sh(k, "config", "user.email", "kb@localhost"); sh(k, "add", "-A")
    sh(k, "commit", "-q", "-m", "init")
    return k


def setup(rate="1000/60"):
    tmp = tempfile.mkdtemp(prefix="brainy_svc_")
    dbp = os.path.join(tmp, "brainy.db")
    conn = db.init_db(dbp)
    admin = acl.create_principal(conn, "USER", "admin", m.ADMIN)
    for k in ("tools", "systems", "shared", "spaceA", "spaceB"):
        spaces.create_space(conn, admin["id"], k, k)
    reader = acl.create_principal(conn, "USER", "reader", m.READER)
    editor = acl.create_principal(conn, "USER", "editor", m.EDITOR)
    agent = acl.create_principal(conn, "AGENT", "agent", m.AGENT)
    acl.grant_permission(conn, admin["id"], "tools", reader["id"], can_read=1)
    acl.grant_permission(conn, admin["id"], "tools", editor["id"], can_read=1, can_write=1)
    acl.grant_permission(conn, admin["id"], "spaceA", agent["id"],
                         can_read=1, can_create_tasks=1, can_claim_tasks=1, can_complete_tasks=1)
    tok = {r["name"]: tokens.create_service_token(conn, r["id"])["token"]
           for r in (reader, editor, agent, admin)}
    conn.close()
    kroot = mini_kb()
    svc = service.BrainyService(dbp, kroot, rate_limit=rate)
    return dict(tmp=tmp, dbp=dbp, kroot=kroot, svc=svc,
                ids=dict(admin=admin["id"], reader=reader["id"], editor=editor["id"],
                         agent=agent["id"]), tok=tok)


def call(svc, tool, params, token=None):
    hdr = ("Bearer " + token) if token else None
    return svc.handle("POST", "/rpc", hdr, json.dumps({"tool": tool, "params": params}).encode())


S = setup()
svc = S["svc"]

# A: health
st, obj = svc.handle("GET", "/health", None, b"")
check("A health localhost", st == 200 and obj["status"] == "ok" and "tools" in obj)

# B/C: kein/falscher Token -> 401
check("B ohne Token -> 401", call(svc, "list_documents", {})[0] == 401)
check("C falscher Token -> 401", call(svc, "list_documents", {}, "bk_dead.WRONG")[0] == 401)

# D: revoked -> 401
tc = db.connect(S["dbp"])
rev = tokens.create_service_token(tc, S["ids"]["reader"])
tokens.revoke_service_token(tc, rev["token_id"])
check("D revoked -> 401", call(svc, "list_documents", {}, rev["token"])[0] == 401)

# E: expired -> 401
exp = tokens.create_service_token(tc, S["ids"]["reader"], expires_at=PAST)
check("E expired -> 401", call(svc, "list_documents", {}, exp["token"])[0] == 401)

# F: READER list/read/search
r = S["tok"]["reader"]
st1, o1 = call(svc, "list_documents", {}, r)
st2, o2 = call(svc, "get_document", {"path": "tools/demo-bot.md"}, r)
st3, o3 = call(svc, "search_knowledge", {"query": "demo-bot"}, r)
check("F READER list/read/search",
      st1 == 200 and any(d["path"] == "tools/demo-bot.md" for d in o1["result"]["documents"])
      and st2 == 200 and "Demo-Bot" in o2["result"]["content"]
      and st3 == 200 and o3["result"]["hits"])

# G: READER write -> 403
head = gitops.head_commit(S["kroot"])
st, o = call(svc, "write_document",
             {"path": "tools/demo-bot.md", "content": "# x\n",
              "expected_git_commit": head, "commit_message": "m"}, r)
check("G READER write -> 403", st == 403 and o["error"]["code"] == "forbidden")

# H: AGENT Task-Liste nur erlaubter Space
tasks.create_task(tc, S["ids"]["admin"], "spaceA", "TA", type="ops")
tasks.create_task(tc, S["ids"]["admin"], "spaceB", "TB", type="ops")
ag = S["tok"]["agent"]
check("H AGENT list_tasks spaceA ok / spaceB 403",
      call(svc, "list_tasks", {"space": "spaceA"}, ag)[0] == 200 and
      call(svc, "list_tasks", {"space": "spaceB"}, ag)[0] == 403)

# I: AGENT Claim erlaubt
t = tasks.create_task(tc, S["ids"]["admin"], "spaceA", "claimme", type="ops", execution_mode="AUTO", action_class="INTERNAL_READ")
tasks.set_status(tc, S["ids"]["admin"], t["task_id"], m.READY)
st, o = call(svc, "claim_task", {"task_id": t["task_id"]}, ag)
check("I AGENT claim erlaubt", st == 200 and o["result"]["claim_token"])
claim_tok = o["result"]["claim_token"]

# J: AGENT fremder Space -> 403
check("J AGENT fremder Space (create/claim spaceB) -> 403",
      call(svc, "create_task", {"space": "spaceB", "title": "x"}, ag)[0] == 403)

# K: EDITOR Knowledge-Write
ed = S["tok"]["editor"]
st, o = call(svc, "write_document",
             {"path": "tools/demo-bot.md", "content": "# Demo-Bot v2\n",
              "expected_git_commit": head, "commit_message": "v2"}, ed)
check("K EDITOR write -> Commit", st == 200 and o["result"]["commit"])
head2 = o["result"]["commit"]

# L: optimistic conflict
st, o = call(svc, "write_document",
             {"path": "tools/demo-bot.md", "content": "# stale\n",
              "expected_git_commit": head, "commit_message": "stale"}, ed)
check("L optimistic conflict -> 409", st == 409 and o["error"]["code"] == "conflict")

# M: Secret-Write blockiert
st, o = call(svc, "write_document",
             {"path": "tools/demo-bot.md",
              "content": "# x\n-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n",
              "expected_git_commit": head2, "commit_message": "sek"}, ed)
check("M Secret-Write -> 400", st == 400 and o["error"]["code"] == "invalid_request")

# N: Path traversal
st, o = call(svc, "get_document", {"path": "../../etc/passwd"}, ed)
check("N Path traversal -> 400", st == 400)

# O: Rate limit
S2 = setup(rate="3/60"); svc2 = S2["svc"]; r2 = S2["tok"]["reader"]
codes = [call(svc2, "list_documents", {}, r2)[0] for _ in range(4)]
check("O Rate limit greift (4. -> 429)", codes[:3] == [200, 200, 200] and codes[3] == 429, str(codes))

# P: keine Tokens im Audit
tc2 = db.connect(S["dbp"])
rows = tc2.execute("SELECT actor, action, object_id, metadata FROM audit_events").fetchall()
sec_reader = S["tok"]["reader"].split(".", 1)[1]
leak = any(sec_reader in " ".join(str(x) for x in row) for row in rows)
mcp_actions = {row["action"] for row in rows}
check("P keine Tokens im Audit + mcp-Events vorhanden",
      not leak and "mcp_tool_called" in mcp_actions)

# Q: Doppel-Claim
st1, _ = call(svc, "claim_task", {"task_id": t["task_id"]}, ag)   # bereits geclaimt (I)
check("Q Doppel-Claim verhindert -> 409", st1 == 409)

# R: stale claim_token
st, o = call(svc, "complete_task",
             {"task_id": t["task_id"], "claim_token": "STALE"}, ag)
check("R stale claim_token -> 409 invalid_claim",
      st == 409 and o["error"]["code"] == "invalid_claim")

# S: complete idempotent
c1 = call(svc, "complete_task", {"task_id": t["task_id"], "claim_token": claim_tok,
                                 "result": "ok"}, ag)
c2 = call(svc, "complete_task", {"task_id": t["task_id"], "claim_token": claim_tok,
                                 "result": "ok"}, ag)
n_comp = len(audit.list_events(tc2, object_id=t["task_id"], action="task_completed"))
check("S complete idempotent", c1[0] == 200 and c2[0] == 200 and n_comp == 1, "comp=%d" % n_comp)

# T: localhost-Guard + MCP-Happy-Path (Integration)
guard_ok = False
try:
    service.run_server(svc, "0.0.0.0", 9, allow_public=False)
except BrainyError:
    guard_ok = True
except Exception:
    guard_ok = False
check("T localhost-Guard (0.0.0.0 verweigert) + Task-Complete-Integration",
      guard_ok and tasks.get_task(tc2, t["task_id"])["status"] == m.COMPLETED)

print("\nGESAMT: %d PASS, %d FAIL" % (_ok[0], _fail[0]))
sys.exit(0 if _fail[0] == 0 else 1)
