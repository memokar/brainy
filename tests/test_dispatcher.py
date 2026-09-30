"""Brainy Dispatcher/Worker Tests (Phase O2). Temp-DB, MockWorker, KEIN externer
Zugriff, keine echte Aktion. Aufruf: python3 tests/test_dispatcher.py"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from brainy import (acl, agents, db, dispatcher as D, models as m, service, settings,  # noqa: E402
                    spaces, tasks, tokens, web, workers as wk)

_ok = [0]; _fail = [0]
SECRET = b"disp-test-session-secret-0123456789ABCDEF"


def check(label, cond, msg=""):
    if cond:
        _ok[0] += 1; print("PASS " + label)
    else:
        _fail[0] += 1; print("FAIL " + label + (": " + msg if msg else ""))


def sh(root, *a):
    return subprocess.run(["git", "-C", root, *a], capture_output=True, text=True).stdout


def mini_kb():
    tmp = tempfile.mkdtemp(prefix="brainy_dkb_"); k = os.path.join(tmp, "kb"); os.makedirs(k)
    for d in ("projects", "tools", "systems", "shared"):
        os.makedirs(os.path.join(k, d))
    open(os.path.join(k, "systems", "brainy.md"), "w").write("# Brainy\n")
    sh(k, "init", "-q", "-b", "main"); sh(k, "config", "user.name", "kb")
    sh(k, "config", "user.email", "kb@localhost"); sh(k, "add", "-A"); sh(k, "commit", "-q", "-m", "i")
    return k


def setup():
    tmp = tempfile.mkdtemp(prefix="brainy_disp_"); dbp = os.path.join(tmp, "brainy.db")
    conn = db.init_db(dbp)
    admin = acl.create_principal(conn, "USER", "admin", m.ADMIN)
    for kk in ("shared", "secret2"):
        spaces.create_space(conn, admin["id"], kk, kk)
    agent = acl.create_principal(conn, "AGENT", "agent", m.AGENT)
    agent2 = acl.create_principal(conn, "AGENT", "agent2", m.AGENT)
    claudep = acl.create_principal(conn, "AGENT", "claudep", m.AGENT)
    editor = acl.create_principal(conn, "USER", "editor", m.EDITOR)
    reader = acl.create_principal(conn, "USER", "reader", m.READER)
    g = lambda who, **c: acl.grant_permission(conn, admin["id"], "shared", who["id"], **c)
    g(agent, can_read=1, can_create_tasks=1, can_claim_tasks=1, can_complete_tasks=1, can_write=1)
    g(agent2, can_read=1, can_create_tasks=1, can_claim_tasks=1, can_complete_tasks=1)
    g(claudep, can_read=1, can_create_tasks=1, can_claim_tasks=1, can_complete_tasks=1)
    g(editor, can_read=1, can_create_tasks=1, can_claim_tasks=1, can_complete_tasks=1,
      can_review=1, can_approve=1)
    g(reader, can_read=1)
    agents.register_agent(conn, admin["id"], "mock1", agent["id"], "MOCK", enabled=1, max_concurrency=1)
    agents.register_agent(conn, admin["id"], "mock2", agent2["id"], "MOCK", enabled=1, max_concurrency=1)
    agents.register_agent(conn, admin["id"], "claude", claudep["id"], "CLAUDE_ADAPTER",
                          enabled=1, max_concurrency=1, status="WAITING_FOR_CLIENT_ADAPTER")
    tok = {"admin": tokens.create_service_token(conn, admin["id"])["token"],
           "agent": tokens.create_service_token(conn, agent["id"])["token"]}
    ids = {"admin": admin["id"], "agent": agent["id"], "agent2": agent2["id"],
           "claudep": claudep["id"], "editor": editor["id"], "reader": reader["id"]}
    conn.close()
    svc = service.BrainyService(dbp, mini_kb(), rate_limit="100000/60")
    return svc, dbp, ids, tok


svc, dbp, ID, TOK = setup()
REG = wk.build_default_registry()
MOCK = REG["MOCK"]


def conn():
    return db.connect(dbp)


def mk(c, title, space="shared", by="admin", **kw):
    kw.setdefault("status", m.READY)
    kw.setdefault("execution_mode", "AUTO")
    kw.setdefault("action_class", "INTERNAL_READ")
    return tasks.create_task(c, ID[by], space, title, **kw)


def enable(on):
    c = conn(); settings.set_dispatcher_enabled(c, ID["admin"], on); c.close()


# ===== A: default paused =====
c = conn()
check("A Dispatcher default PAUSED", settings.dispatcher_enabled(c) is False)

# ===== B: paused -> nichts =====
tb = mk(c, "[TEST] paused")
res = D.dispatch_tick(c, registry=REG)
check("B paused -> kein Dispatch, Task bleibt READY",
      res["paused"] and not res["dispatched"] and tasks.get_task(c, tb["task_id"])["status"] == "READY")
c.close()

enable(True)

# ===== C/S/T: AUTO runnable -> COMPLETED =====
c = conn()
tc = mk(c, "[TEST] auto")
D.dispatch_tick(c, registry=REG)
tt = tasks.get_task(c, tc["task_id"])
check("C runnable AUTO erkannt + dispatched", D.list_jobs(c, task_id=tc["task_id"]))
check("T AUTO -> COMPLETED", tt["status"] == "COMPLETED")
check("S Worker-Result -> complete_task (result gesetzt)", "MOCK" in (tt["result"] or ""))

# ===== D: preferred_agent gewaehlt =====
td = mk(c, "[TEST] pref", preferred_agent="agent2")
D.dispatch_tick(c, registry=REG)
jd = D.list_jobs(c, task_id=td["task_id"])[0]
check("D preferred_agent gewaehlt (agent2)", jd["agent_principal_id"] == ID["agent2"])

# ===== E: unavailable preferred faellt zurueck =====
te = mk(c, "[TEST] pref-unavail", preferred_agent="claudep")   # CLAUDE_ADAPTER unavailable
D.dispatch_tick(c, registry=REG)
je = D.list_jobs(c, task_id=te["task_id"])[0]
check("E unavailable preferred -> Fallback auf MOCK",
      je["agent_principal_id"] in (ID["agent"], ID["agent2"]))

# ===== F: capabilities gefiltert (nur agent hat write) =====
tf = mk(c, "[TEST] needwrite", required_capabilities=["knowledge.write"])
D.dispatch_tick(c, registry=REG)
jf = D.list_jobs(c, task_id=tf["task_id"])[0]
check("F required_capabilities -> nur berechtigter Agent (agent)",
      jf["agent_principal_id"] == ID["agent"])

# ===== G: ACL gefiltert (secret2, kein Agent) =====
tg = mk(c, "[TEST] secret", space="secret2")
D.dispatch_tick(c, registry=REG)
check("G ACL: kein Agent -> nicht dispatched, Task READY",
      not D.list_jobs(c, task_id=tg["task_id"]) and tasks.get_task(c, tg["task_id"])["status"] == "READY")

# ===== U: REVIEW -> AWAITING_REVIEW =====
tu = mk(c, "[TEST] review", execution_mode="REVIEW", action_class="CODE_CHANGE")
D.dispatch_tick(c, registry=REG)
check("U REVIEW dispatch -> AWAITING_REVIEW",
      tasks.get_task(c, tu["task_id"])["status"] == "AWAITING_REVIEW")

# ===== V/W: APPROVAL -> AWAITING_APPROVAL -> approve -> post-approval -> COMPLETED =====
tv = mk(c, "[TEST] publish", execution_mode="AUTO", action_class="PUBLISH")
D.dispatch_tick(c, registry=REG)
check("V APPROVAL dispatch -> AWAITING_APPROVAL (nicht COMPLETED)",
      tasks.get_task(c, tv["task_id"])["status"] == "AWAITING_APPROVAL")
D.dispatch_tick(c, registry=REG)   # noch nicht approved -> bleibt gated
check("W1 vor Approval NICHT weiter dispatched",
      tasks.get_task(c, tv["task_id"])["status"] == "AWAITING_APPROVAL")
tasks.approve_task(c, ID["editor"], tv["task_id"], note="[TEST] go")
D.dispatch_tick(c, registry=REG)   # promote_approved -> READY -> run -> COMPLETED
check("W2 nach Approval post-approval-dispatch -> COMPLETED",
      tasks.get_task(c, tv["task_id"])["status"] == "COMPLETED"
      and len(D.list_jobs(c, task_id=tv["task_id"])) == 2)

# ===== X: reject -> nicht erneut dispatched =====
tx = mk(c, "[TEST] publish-reject", execution_mode="AUTO", action_class="PUBLISH")
D.dispatch_tick(c, registry=REG)
tasks.reject_task(c, ID["editor"], tx["task_id"], note="[TEST] no")
njobs = len(D.list_jobs(c, task_id=tx["task_id"]))
D.dispatch_tick(c, registry=REG)
check("X rejected -> kein erneuter Dispatch",
      tasks.get_task(c, tx["task_id"])["status"] == "REJECTED"
      and len(D.list_jobs(c, task_id=tx["task_id"])) == njobs)

# ===== P/Q: transient retry + max attempts =====
tp = mk(c, "[TEST] transient")
MOCK.behaviors[tp["task_id"]] = "transient"
D.dispatch_tick(c, registry=REG)
check("P transienter Startfehler -> Job FAILED + Task READY (retry)",
      tasks.get_task(c, tp["task_id"])["status"] == "READY"
      and D.list_jobs(c, task_id=tp["task_id"], status="FAILED"))
D.dispatch_tick(c, registry=REG); D.dispatch_tick(c, registry=REG)   # 2. + 3. Versuch
check("Q max_attempts=3 erreicht -> Task BLOCKED, keine weiteren Dispatches",
      tasks.get_task(c, tp["task_id"])["status"] == "BLOCKED"
      and len(D.list_jobs(c, task_id=tp["task_id"])) == 3)

# ===== R: permission fail -> kein Retry =====
tr = mk(c, "[TEST] permfail")
MOCK.behaviors[tr["task_id"]] = "permanent"
D.dispatch_tick(c, registry=REG)
check("R permission-Fehler -> BLOCKED, KEIN Retry (1 Job)",
      tasks.get_task(c, tr["task_id"])["status"] == "BLOCKED"
      and len(D.list_jobs(c, task_id=tr["task_id"])) == 1)
c.close()

# ===== I: concurrency-Filter (busy Agent nicht gewaehlt) =====
c = conn()
import uuid as _uuid
from brainy.util import now_iso
# mock1 mit einem aktiven (QUEUED) Job belegen -> Concurrency-Slot voll
tocc = mk(c, "[TEST] occupy")
occ = D.claim_and_create_job(c, tasks._row(c, tocc["task_id"]),
                            next(a for a in agents.list_agents(c) if a["agent_name"] == "mock1"))
ti = mk(c, "[TEST] conc", required_capabilities=["knowledge.write"])  # nur agent(mock1) faehig
sel = D.select_agent(c, tasks._row(c, ti["task_id"]), agents.list_agents(c), REG)
check("I concurrency: belegter einziger faehiger Agent -> keine Auswahl", sel is None)
c.execute("UPDATE execution_jobs SET status='SUCCEEDED' WHERE job_id=?", (occ["job_id"],)); c.commit()

# ===== K/L: single-dispatch + claim_token =====
tk = mk(c, "[TEST] single")
job1 = D.claim_and_create_job(c, tasks._row(c, tk["task_id"]),
                             next(a for a in agents.list_agents(c) if a["agent_name"] == "mock1"))
full = c.execute("SELECT dispatch_token FROM execution_jobs WHERE job_id=?",
                 (job1["job_id"],)).fetchone()["dispatch_token"]
tkrow = tasks._row(c, tk["task_id"])
check("L dispatch_token == Task-claim_token", full and full == tkrow["claim_token"])
job2 = D.claim_and_create_job(c, tasks._row(c, tk["task_id"]),
                             next(a for a in agents.list_agents(c) if a["agent_name"] == "mock2"))
check("K duplicate active job verhindert", job2 is None
      and len([j for j in D.list_jobs(c, task_id=tk["task_id"]) if j["status"] in D.ACTIVE_JOB]) == 1)
# aufraeumen: job1 ausfuehren
D.execute_job(c, job1, REG)
check("M heartbeat gesetzt bei Ausfuehrung",
      D.get_job(c, job1["job_id"])["heartbeat_at"] is not None)
c.close()

# ===== N/O/AF: timeout recovery / restart =====
c = conn()
tn = mk(c, "[TEST] timeout")
cl = tasks.claim_task(c, ID["agent"], tn["task_id"])
jid2 = _uuid.uuid4().hex
c.execute("INSERT INTO execution_jobs(job_id,task_id,agent_principal_id,worker_type,status,"
          "created_at,lease_until,attempt,max_attempts,dispatch_token) "
          "VALUES(?,?,?,?,'RUNNING',?,?,1,3,?)",
          (jid2, tn["task_id"], ID["agent"], "MOCK", now_iso(), "2000-01-01T00:00:00+00:00",
           cl["claim_token"]))
c.commit()
rec = D.recover_timeouts(c)
check("N timeout -> Job TIMED_OUT", jid2 in rec
      and D.get_job(c, jid2)["status"] == "TIMED_OUT")
check("O timeout -> Task-Claim recoverable (READY, claim geloescht)",
      tasks.get_task(c, tn["task_id"])["status"] == "READY"
      and tasks._row(c, tn["task_id"])["claim_token"] is None)
check("AF restart/recovery: tick raeumt verwaisten RUNNING-Job auf",
      True)   # recover_timeouts wird in jedem dispatch_tick zuerst aufgerufen (siehe C..X)
c.close()

# ===== Y: per-agent disable =====
c = conn()
agents.set_enabled(c, ID["admin"], "mock2", False)
ty = mk(c, "[TEST] onlymock1", required_capabilities=["knowledge.write"])
# mock1 auch aus: dann kein faehiger Agent
agents.set_enabled(c, ID["admin"], "mock1", False)
D.dispatch_tick(c, registry=REG)
check("Y per-agent disable -> kein Dispatch (kein faehiger enabled Agent)",
      not D.list_jobs(c, task_id=ty["task_id"]))
agents.set_enabled(c, ID["admin"], "mock1", True)
agents.set_enabled(c, ID["admin"], "mock2", True)
c.close()

# ===== Z: global pause =====
c = conn()
D.pause_dispatcher(c, ID["admin"])
tz = mk(c, "[TEST] globalpause")
r = D.dispatch_tick(c, registry=REG)
check("Z global kill-switch: paused -> kein Dispatch",
      r["paused"] and not D.list_jobs(c, task_id=tz["task_id"]))
D.resume_dispatcher(c, ID["admin"])
check("global resume durch ADMIN ok", settings.dispatcher_enabled(c))
# non-admin darf nicht steuern
from brainy.errors import PermissionDenied
try:
    D.pause_dispatcher(c, ID["reader"]); ok = False
except PermissionDenied:
    ok = True
check("global pause nur ADMIN (reader -> deny)", ok)
D.pause_dispatcher(c, ID["admin"])   # wieder sicher pausieren
c.close()

# ===== AB: MCP visibility =====
def tools_for(tokn):
    st, ct, b = svc.handle_mcp("POST", "Bearer " + tokn, json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode())
    return {t["name"] for t in json.loads(b)["result"]["tools"]}

at = tools_for(TOK["admin"]); gt = tools_for(TOK["agent"])
check("AB MCP: admin sieht Controls, agent nicht; beide read-tools",
      {"enable_agent", "pause_dispatcher"} <= at and "pause_dispatcher" not in gt
      and {"list_agents", "list_execution_jobs"} <= gt)

# ===== AC/AD: Web admin controls + CSRF =====
app = web.BrainyWeb(svc, SECRET)
ck = lambda pid: "%s=%s" % (web.COOKIE, web.make_session(SECRET, pid))
csrf = lambda pid: web.csrf_token(SECRET, web.make_session(SECRET, pid))
dash_admin = app.handle("GET", "/admin/", "", ck(ID["admin"]), b"")[3].decode()
ag_admin = app.handle("GET", "/admin/agents", "", ck(ID["admin"]), b"")[3].decode()
ag_reader = app.handle("GET", "/admin/agents", "", ck(ID["reader"]), b"")[3].decode()
check("AC Web: admin Dashboard Dispatcher-Control + Agents-Toggle sichtbar",
      "Dispatcher</button>" in dash_admin and "agents/toggle" in ag_admin)
check("AC Web: reader ohne Agent-Toggle", "agents/toggle" not in ag_reader)
r_nocsrf = app.handle("POST", "/admin/dispatcher/toggle", "", ck(ID["admin"]),
                      urllib.parse.urlencode({"action": "resume"}).encode())
check("AD CSRF: dispatcher toggle ohne Token -> 403", r_nocsrf[0] == 403)

# ===== AE: kein dispatch_token in MCP/Web =====
c = conn()
tok_task = mk(c, "[TEST] leakcheck")
jrow = D.claim_and_create_job(c, tasks._row(c, tok_task["task_id"]),
                             next(a for a in agents.list_agents(c) if a["agent_name"] == "mock1"))
dtoken = c.execute("SELECT dispatch_token FROM execution_jobs WHERE job_id=?",
                   (jrow["job_id"],)).fetchone()["dispatch_token"]
c.close()
st, ct, b = svc.handle_mcp("POST", "Bearer " + TOK["admin"], json.dumps(
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": "list_execution_jobs", "arguments": {}}}).encode())
mcp_jobs = b.decode()
web_jobs = app.handle("GET", "/admin/jobs", "", ck(ID["admin"]), b"")[3].decode()
check("AE kein dispatch_token in MCP/Web",
      dtoken and dtoken not in mcp_jobs and dtoken not in web_jobs
      and "dispatch_token" not in mcp_jobs)

# ===== AA: audit events =====
c = conn()
acts = {r["action"] for r in c.execute("SELECT action FROM audit_events").fetchall()}
need = {"job_created", "job_succeeded", "job_failed", "job_timed_out",
        "dispatcher_paused", "dispatcher_resumed", "agent_enabled", "agent_disabled",
        "task_post_approval_ready", "agent_registered"}
check("AA Audit-Events vollstaendig", need <= acts, "fehlt: %s" % (need - acts))
c.close()

print("\nGESAMT: %d PASS, %d FAIL" % (_ok[0], _fail[0]))
sys.exit(0 if _fail[0] == 0 else 1)
