"""Brainy Web/Admin Tests (Phase E). web.BrainyWeb.handle direkt (kein Socket).
Temp-DB/Test-Repo, KEIN produktiver Knowledge-Write. Aufruf: python3 tests/test_web.py"""
import json
import os
import subprocess
import sys
import tempfile
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from brainy import acl, db, knowledge, models as m, service, spaces, tasks, tokens, web  # noqa: E402

_ok = [0]; _fail = [0]
SECRET = b"brainy-test-session-secret-0123456789ABCDEF"


def check(label, cond, msg=""):
    if cond:
        _ok[0] += 1; print("PASS " + label)
    else:
        _fail[0] += 1; print("FAIL " + label + (": " + msg if msg else ""))


def sh(root, *a):
    return subprocess.run(["git", "-C", root, *a], capture_output=True, text=True).stdout


def mini_kb():
    tmp = tempfile.mkdtemp(prefix="brainy_webkb_"); k = os.path.join(tmp, "kb"); os.makedirs(k)
    for d in ("projects", "tools", "systems", "shared"):
        os.makedirs(os.path.join(k, d))
    open(os.path.join(k, "systems", "brainy.md"), "w").write("# Brainy\n\nBrainy backbone.\n")
    open(os.path.join(k, "tools", "x.md"), "w").write("# Tool X\n\nurspruenglich.\n")
    sh(k, "init", "-q", "-b", "main"); sh(k, "config", "user.name", "kb")
    sh(k, "config", "user.email", "kb@localhost"); sh(k, "add", "-A"); sh(k, "commit", "-q", "-m", "init")
    return k


def setup():
    tmp = tempfile.mkdtemp(prefix="brainy_web_"); dbp = os.path.join(tmp, "brainy.db")
    conn = db.init_db(dbp)
    admin = acl.create_principal(conn, "USER", "admin", m.ADMIN)
    for kk in ("tools", "systems", "shared", "spaceB"):
        spaces.create_space(conn, admin["id"], kk, kk)
    reader = acl.create_principal(conn, "USER", "reader", m.READER)
    editor = acl.create_principal(conn, "USER", "editor", m.EDITOR)
    agent = acl.create_principal(conn, "AGENT", "agent", m.AGENT)
    acl.grant_permission(conn, admin["id"], "tools", reader["id"], can_read=1)
    acl.grant_permission(conn, admin["id"], "tools", editor["id"], can_read=1, can_write=1)
    acl.grant_permission(conn, admin["id"], "shared", agent["id"],
                         can_read=1, can_create_tasks=1, can_claim_tasks=1, can_complete_tasks=1)
    admin_tok = tokens.create_service_token(conn, admin["id"], description="admin-web")["token"]
    agent_secret = tokens.create_service_token(conn, agent["id"], description="agent")["token"]
    conn.close()
    svc = service.BrainyService(dbp, mini_kb(), rate_limit="100000/60")
    app = web.BrainyWeb(svc, SECRET)
    ids = {"admin": admin["id"], "reader": reader["id"], "editor": editor["id"],
           "agent": agent["id"]}
    return svc, app, dbp, ids, {"admin": admin_tok, "agent": agent_secret}


def cookie_for(pid):
    if pid is None:
        return None
    return "%s=%s" % (web.COOKIE, web.make_session(SECRET, pid))


def csrf_for(pid):
    return web.csrf_token(SECRET, web.make_session(SECRET, pid))
    # Hinweis: make_session enthaelt exp -> csrf muss aus DEMSELBEN Wert stammen.


def get(app, path, query="", pid=None, cookie=None):
    ck = cookie if cookie is not None else cookie_for(pid)
    return app.handle("GET", path, query, ck, b"")


def post(app, path, form, pid=None, cookie=None, csrf=None):
    ck = cookie if cookie is not None else cookie_for(pid)
    return app.handle("POST", path, "", ck, urllib.parse.urlencode(form).encode())


def body_of(res):
    return res[3].decode("utf-8", "replace")


def loc(res):
    for k, v in res[2]:
        if k == "Location":
            return v
    return None


def setcookie(res):
    for k, v in res[2]:
        if k == "Set-Cookie":
            return v
    return None


svc, app, dbp, ID, TOK = setup()
conn0 = db.connect(dbp)
HEAD0 = knowledge.get_git_status(conn0, ID["admin"], root=svc.knowledge_root)["head"]

# Fuer Sessions mit gueltigem CSRF verwenden wir EIN festes Cookie pro Principal,
# damit make_session (mit exp) zwischen Cookie und CSRF konsistent ist.
CK = {name: cookie_for(pid) for name, pid in ID.items()}


def sess_csrf(name):
    return web.csrf_token(SECRET, CK[name].split("=", 1)[1])


# A. unauth Admin -> Login-Redirect
rA = get(app, "/admin/", pid=None)
check("A unauth /admin/ -> 303 login", rA[0] == 303 and rA[2] and loc(rA) == "/admin/login")

# P. unbekannte Identity (falsches Token) -> deny 401
rP = app.handle("POST", "/admin/login", "", None, urllib.parse.urlencode(
    {"token": "bk_nope.WRONG"}).encode())
check("P Login falsches Token -> 401", rP[0] == 401)

# P+ gueltiger Login -> Set-Cookie + Session funktioniert
rL = app.handle("POST", "/admin/login", "", None, urllib.parse.urlencode(
    {"token": TOK["admin"]}).encode())
sc = setcookie(rL)
check("Login gueltiges Token -> 303 + Set-Cookie HttpOnly/Secure",
      rL[0] == 303 and sc and "HttpOnly" in sc and "Secure" in sc)
login_cookie = "%s=%s" % (web.COOKIE, sc.split("=", 1)[1].split(";", 1)[0]) if sc else None
rLd = get(app, "/admin/", cookie=login_cookie)
check("Login-Cookie -> Dashboard 200", rLd[0] == 200 and "Dashboard" in body_of(rLd))

# E. ADMIN Dashboard
rE = get(app, "/admin/", cookie=CK["admin"])
check("E ADMIN Dashboard 200", rE[0] == 200 and "Dashboard" in body_of(rE)
      and "Tasks" in body_of(rE))

# B. READER read-only (Tasks-Liste, KEIN Create-Formular)
rB = get(app, "/admin/tasks", cookie=CK["reader"])
check("B READER Tasks read-only (kein Create)",
      rB[0] == 200 and "Neuer Task" not in body_of(rB))

# C. READER kann nicht schreiben (create -> 403)
rC = post(app, "/admin/tasks/create",
          {"space": "tools", "title": "x", "csrf": sess_csrf("reader")}, cookie=CK["reader"])
check("C READER create -> 403", rC[0] == 403)

# O. CSRF: Write ohne Token -> deny
rO = post(app, "/admin/tasks/create", {"space": "shared", "title": "x"}, cookie=CK["admin"])
check("O CSRF fehlend -> 403", rO[0] == 403 and "CSRF" in body_of(rO))

# F. Task Create (ADMIN)
rF = post(app, "/admin/tasks/create",
          {"space": "shared", "title": "Phase E smoke", "type": "chore",
           "status": "OPEN", "csrf": sess_csrf("admin")}, cookie=CK["admin"])
tid = loc(rF).split("id=")[-1] if rF[0] == 303 else None
check("F Task create -> 303 + Task existiert",
      rF[0] == 303 and tid and tasks.get_task(db.connect(dbp), tid) is not None)

# G. OPEN -> READY
rG = post(app, "/admin/tasks/action",
          {"id": tid, "action": "ready", "csrf": sess_csrf("admin")}, cookie=CK["admin"])
check("G OPEN->READY", rG[0] == 303 and
      tasks.get_task(db.connect(dbp), tid)["status"] == "READY")

# H. aktiven Claim NICHT ueberschreiben
c2 = db.connect(dbp)
tclaim = tasks.create_task(c2, ID["agent"], "shared", "claim-me", status=m.READY)
tasks.claim_task(c2, ID["agent"], tclaim["task_id"])
c2.close()
rH = post(app, "/admin/tasks/action",
          {"id": tclaim["task_id"], "action": "cancel", "csrf": sess_csrf("admin")},
          cookie=CK["admin"])
still = tasks.get_task(db.connect(dbp), tclaim["task_id"])["status"]
check("H aktiver Claim -> 409, Status bleibt CLAIMED",
      rH[0] == 409 and still == "CLAIMED")

# D. EDITOR Knowledge-Write im Temp-Repo
c3 = db.connect(dbp)
head_now = knowledge.get_git_status(c3, ID["editor"], root=svc.knowledge_root)["head"]
c3.close()
rD = post(app, "/admin/knowledge/save",
          {"path": "tools/x.md", "content": "# Tool X\n\nGEAENDERT durch EDITOR.\n",
           "expected_git_commit": head_now, "commit_message": "web edit",
           "csrf": sess_csrf("editor")}, cookie=CK["editor"])
c3 = db.connect(dbp)
newdoc = knowledge.get_document(c3, ID["editor"], "tools/x.md", root=svc.knowledge_root)
c3.close()
check("D EDITOR write -> 303 + Inhalt geaendert",
      rD[0] == 303 and "GEAENDERT" in newdoc["content"])

# L. Optimistic Conflict (stale expected_git_commit)
rL2 = post(app, "/admin/knowledge/save",
           {"path": "tools/x.md", "content": "# Tool X\n\nnochmal.\n",
            "expected_git_commit": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "commit_message": "stale", "csrf": sess_csrf("editor")}, cookie=CK["editor"])
check("L Optimistic Conflict -> 400", rL2[0] == 400 and "veraltet" in body_of(rL2).lower()
      or rL2[0] == 400)

# K. Secret-Guard blockiert Write
c4 = db.connect(dbp)
head2 = knowledge.get_git_status(c4, ID["editor"], root=svc.knowledge_root)["head"]
c4.close()
rK = post(app, "/admin/knowledge/save",
          {"path": "tools/x.md",
           "content": "# Tool X\n\ntoken = \"ghp_" + "A" * 30 + "\"\n",
           "expected_git_commit": head2, "commit_message": "secret",
           "csrf": sess_csrf("editor")}, cookie=CK["editor"])
check("K Secret-Write blockiert -> 400", rK[0] == 400)

# I. Knowledge Search
rI = get(app, "/admin/knowledge/search", "q=brainy", cookie=CK["admin"])
check("I Knowledge Search -> Treffer systems/brainy.md",
      rI[0] == 200 and "systems/brainy.md" in body_of(rI))

# J. History + Diff (tools/x.md hat nun >=2 Commits)
rJ = get(app, "/admin/knowledge/history", "path=tools/x.md", cookie=CK["admin"])
hist = knowledge.get_document_history(db.connect(dbp), ID["admin"], "tools/x.md",
                                      root=svc.knowledge_root)
check("J History 200 + mehrere Commits", rJ[0] == 200 and len(hist) >= 2)
if len(hist) >= 2:
    rJd = get(app, "/admin/knowledge/diff",
              "path=tools/x.md&from=%s&to=%s" % (hist[1]["commit"], hist[0]["commit"]),
              cookie=CK["admin"])
    check("J Diff 200 + zeigt Aenderung", rJd[0] == 200 and "GEAENDERT" in body_of(rJd))

# M. Tokenwerte NIEMALS gerendert
rM = get(app, "/admin/tokens", cookie=CK["admin"])
bM = body_of(rM)
admin_secret = TOK["admin"].split(".", 1)[1]
agent_secret = TOK["agent"].split(".", 1)[1]
check("M Tokens-UI ohne Secret/Hash",
      rM[0] == 200 and admin_secret not in bM and agent_secret not in bM
      and "token_hash" not in bM)

# Principals-UI: keine Tokenwerte, Rollen sichtbar
rPr = get(app, "/admin/principals", cookie=CK["admin"])
check("Principals-UI 200 + Rollen, keine Secrets",
      rPr[0] == 200 and "ADMIN" in body_of(rPr) and admin_secret not in body_of(rPr))

# READER darf Principals/Tokens NICHT sehen (ADMIN-only)
rRp = get(app, "/admin/principals", cookie=CK["reader"])
check("Principals nur ADMIN (READER -> 403)", rRp[0] == 403)

# N. Audit read-only (ADMIN/EDITOR), keine Mutations-Route
rN = get(app, "/admin/audit", cookie=CK["admin"])
check("N Audit read-only 200 + append-only Hinweis",
      rN[0] == 200 and "append-only" in body_of(rN).lower())
rNx = post(app, "/admin/audit/delete", {"csrf": sess_csrf("admin")}, cookie=CK["admin"])
check("N keine Audit-Mutationsroute (404)", rNx[0] == 404)

# Spaces + ACL sichtbar
rSp = get(app, "/admin/spaces", cookie=CK["admin"])
check("Spaces-UI 200 + ACL", rSp[0] == 200 and "shared" in body_of(rSp))

# 18. ACL beruecksichtigt: READER sieht fremdes Dokument (systems) NICHT
rAcl = get(app, "/admin/knowledge/view", "path=systems/brainy.md", cookie=CK["reader"])
check("ACL: READER ohne systems-Recht -> 403", rAcl[0] == 403)

# Q. /mcp Regression
stq, ctq, bq = svc.handle_mcp("POST", "Bearer " + TOK["admin"], json.dumps(
    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
     "params": {"protocolVersion": "2025-06-18", "capabilities": {}}}).encode())
check("Q /mcp initialize 200", stq == 200 and json.loads(bq)["result"]["serverInfo"]["name"] == "brainy")

# R. /rpc Regression
str_, orr = svc.handle("POST", "/rpc", "Bearer " + TOK["admin"],
                       json.dumps({"tool": "list_spaces", "params": {}}).encode())
check("R /rpc list_spaces 200", str_ == 200 and orr.get("ok") is True)

# S. /health Regression
sts, ohs = svc.handle("GET", "/health", None, b"")
check("S /health 200", sts == 200 and ohs.get("status") == "ok")

print("\nGESAMT: %d PASS, %d FAIL" % (_ok[0], _fail[0]))
sys.exit(0 if _fail[0] == 0 else 1)
