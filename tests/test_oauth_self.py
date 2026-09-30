"""Brainy: OAuth-Selbstfreigabe eingeschraenkter Menschen + Knowledge-Bereich 'team'.
Temp-DB/Temp-KB, kein Netz. Aufruf: python3 tests/test_oauth_self.py"""
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from brainy import acl, db, models as m, oauth, paths, service, spaces, web  # noqa: E402

_ok = [0]; _fail = [0]
SECRET = b"oauth-self-test-secret-0123456789ABCDEFGH"


def check(label, cond, msg=""):
    if cond:
        _ok[0] += 1; print("PASS " + label)
    else:
        _fail[0] += 1; print("FAIL " + label + (": " + msg if msg else ""))


def sh(root, *a):
    return subprocess.run(["git", "-C", root, *a], capture_output=True, text=True).stdout


def mini_kb():
    k = os.path.join(tempfile.mkdtemp(prefix="brainy_selfkb_"), "kb"); os.makedirs(k)
    for d in ("projects", "tools", "systems", "shared", "team"):
        os.makedirs(os.path.join(k, d))
    open(os.path.join(k, "systems", "geheim.md"), "w").write("# Geheim\n\nnur intern\n")
    open(os.path.join(k, "team", "README.md"), "w").write("# Team\n\nGemeinsam.\n")
    sh(k, "init", "-q", "-b", "main"); sh(k, "config", "user.name", "kb")
    sh(k, "config", "user.email", "kb@localhost"); sh(k, "add", "-A"); sh(k, "commit", "-q", "-m", "i")
    return k


def pkce():
    v = secrets.token_urlsafe(48)
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).decode().rstrip("=")


tmp = tempfile.mkdtemp(prefix="brainy_self_"); dbp = os.path.join(tmp, "brainy.db")
conn = db.init_db(dbp)
admin = acl.create_principal(conn, "USER", "admin", m.ADMIN)
for kk in ("shared", "systems", "tools", "projects", "team"):
    spaces.create_space(conn, admin["id"], kk, kk)
acct = acl.create_principal(conn, "AGENT", "claude-account", m.AGENT)
acl.grant_permission(conn, admin["id"], "systems", acct["id"], can_read=1)
alex = acl.create_principal(conn, "USER", "alex", m.EDITOR, metadata={"oauth_self": True})
acl.grant_permission(conn, admin["id"], "team", alex["id"], can_read=1, can_write=1)
plain = acl.create_principal(conn, "USER", "plain", m.EDITOR)            # ohne oauth_self
agentx = acl.create_principal(conn, "AGENT", "agentx", m.AGENT, metadata={"oauth_self": True})
conn.close()
svc = service.BrainyService(dbp, mini_kb(), rate_limit="100000/60")
app = web.BrainyWeb(svc, SECRET)
REDIR = "https://claude.ai/api/mcp/auth_callback"


def ck(p):
    return "%s=%s" % (web.COOKIE, web.make_session(SECRET, p))


def csrf(p):
    return web.csrf_token(SECRET, web.make_session(SECRET, p))


def loc(res):
    return next((v for k, v in res[2] if k.lower() == "location"), None)


def oauth_api(method, path, body=b""):
    return svc.handle_oauth(method, path, "", body)


cid = json.loads(oauth_api("POST", "/oauth/register", json.dumps(
    {"client_name": "Claude", "redirect_uris": [REDIR]}).encode())[3])["client_id"]
SC = "brainy:knowledge:read brainy:knowledge:write brainy:tasks:read brainy:tasks:write"


def flow(principal):
    v, ch = pkce()
    params = {"client_id": cid, "redirect_uri": REDIR, "response_type": "code", "scope": SC,
              "state": "s", "code_challenge": ch, "code_challenge_method": "S256"}
    g = app.handle("GET", "/oauth/authorize", urllib.parse.urlencode(params), ck(principal), b"")
    form = dict(params, csrf=csrf(principal), decision="approve")
    p = app.handle("POST", "/oauth/authorize", "", ck(principal), urllib.parse.urlencode(form).encode())
    return g, p, v


# --- paths
check("paths: team/ erlaubt", paths.normalize_rel("team/x.md") == "team/x.md"
      and paths.space_for_path("team/x.md") == "team")
try:
    paths.normalize_rel("geheim/x.md"); check("paths: fremder Bereich weiter verboten", False)
except paths.PathNotAllowed:
    check("paths: fremder Bereich weiter verboten", True)

# --- Selbstfreigabe
g, p, v = flow(alex["id"])
check("alex Consent-GET 200 zeigt Principal alex", g[0] == 200 and b"alex" in g[3]
      and b"claude-account" not in g[3])
code = urllib.parse.parse_qs(urllib.parse.urlparse(loc(p) or "").query).get("code", [None])[0]
check("alex Consent-POST -> Code", p[0] == 303 and code)
tok = json.loads(oauth_api("POST", "/oauth/token", urllib.parse.urlencode(
    {"grant_type": "authorization_code", "code": code, "client_id": cid,
     "redirect_uri": REDIR, "code_verifier": v}).encode())[3])
AT = tok.get("access_token")
c = db.connect(dbp)
pid_at, _sc = oauth.authenticate_access_token(c, AT)
c.close()
check("alex Token laeuft unter Principal alex (nicht claude-account)", pid_at == alex["id"])

# --- Negativ: ohne Flag / AGENT mit Flag
check("EDITOR ohne oauth_self -> 403", flow(plain["id"])[0][0] == 403)
check("AGENT mit oauth_self -> 403 (nur USER)", flow(agentx["id"])[0][0] == 403)

# --- Admin-Pfad unveraendert
ga, pa, va = flow(admin["id"])
codea = urllib.parse.parse_qs(urllib.parse.urlparse(loc(pa) or "").query).get("code", [None])[0]
ta = json.loads(oauth_api("POST", "/oauth/token", urllib.parse.urlencode(
    {"grant_type": "authorization_code", "code": codea, "client_id": cid,
     "redirect_uri": REDIR, "code_verifier": va}).encode())[3])
c = db.connect(dbp)
pid_a, _ = oauth.authenticate_access_token(c, ta["access_token"])
c.close()
check("ADMIN-Freigabe weiterhin -> claude-account", pid_a == acct["id"])


# --- MCP mit alex-Token: nur team/
def call(token, name, args):
    st, ct, bod = svc.handle_mcp("POST", "Bearer " + token, json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": name, "arguments": args}}).encode())
    r = json.loads(bod)["result"]
    return r.get("isError", False), r["content"][0]["text"]


err, txt = call(AT, "get_document", {"path": "team/README.md"})
check("alex liest team/README.md", not err and "Gemeinsam" in txt, txt[:200])
err, txt = call(AT, "write_document", {"path": "team/notiz.md", "content": "# Notiz\n\nvon alex\n",
                                       "commit_message": "alex notiz"})
check("alex schreibt team/notiz.md", not err, txt[:200])
err, txt = call(AT, "get_document", {"path": "systems/geheim.md"})
check("alex liest systems/ NICHT", err, txt[:200])
err, txt = call(AT, "write_document", {"path": "projects/x.md", "content": "# x\n", "commit_message": "x"})
check("alex schreibt projects/ NICHT", err, txt[:200])
err, txt = call(AT, "list_documents", {})
check("alex list_documents nur team/", not err and "team/" in txt and "systems/" not in txt, txt[:300])
err, txt = call(AT, "search_knowledge", {"query": "intern"})
check("alex search_knowledge findet nichts aus systems/", "geheim" not in txt, txt[:300])
err, txt = call(AT, "create_task", {"space": "team", "title": "t", "description": "d"})
check("alex create_task verboten", err, txt[:200])

# --- Web-Oberflaeche fuer alex gesperrt
r = app.handle("GET", "/admin/", "", ck(alex["id"]), b"")
check("Web /admin/ fuer alex nur Info-Seite", r[0] == 200 and b"gesperrt" in r[3])
for pth in ("/admin/knowledge", "/admin/principals", "/admin/tokens", "/admin/audit", "/admin/tasks",
            "/admin/knowledge/view"):
    r = app.handle("GET", pth, "path=systems/geheim.md", ck(alex["id"]), b"")
    check("Web %s fuer alex 403" % pth, r[0] == 403 and b"nur intern" not in r[3])
r = app.handle("POST", "/admin/knowledge/save", "", ck(alex["id"]),
               urllib.parse.urlencode({"csrf": csrf(alex["id"]), "path": "team/y.md",
                                       "content": "x"}).encode())
check("Web POST fuer alex 403", r[0] == 403)
r = app.handle("GET", "/admin/", "", ck(plain["id"]), b"")
check("Web fuer andere Nicht-Admins unveraendert (keine Info-Sperrseite)", b"gesperrt" not in r[3])

print("\nGESAMT: %d PASS, %d FAIL" % (_ok[0], _fail[0]))
sys.exit(0 if _fail[0] == 0 else 1)
