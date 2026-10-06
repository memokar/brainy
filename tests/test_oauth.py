"""Brainy OAuth-2.1 / MCP-Connector Tests (Phase O6A). Temp-DB, kein echter Cloud-Call.
Aufruf: python3 tests/test_oauth.py"""
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
from brainy import acl, db, models as m, oauth, service, spaces, tokens, web  # noqa: E402

_ok = [0]; _fail = [0]
SECRET = b"oauth-test-session-secret-0123456789ABCDEF"


def check(label, cond, msg=""):
    if cond:
        _ok[0] += 1; print("PASS " + label)
    else:
        _fail[0] += 1; print("FAIL " + label + (": " + msg if msg else ""))


def sh(root, *a):
    return subprocess.run(["git", "-C", root, *a], capture_output=True, text=True).stdout


def mini_kb():
    tmp = tempfile.mkdtemp(prefix="brainy_oakb_"); k = os.path.join(tmp, "kb"); os.makedirs(k)
    for d in ("projects", "tools", "systems", "shared"):
        os.makedirs(os.path.join(k, d))
    open(os.path.join(k, "systems", "brainy.md"), "w").write("# Brainy\n\nBrainy backbone.\n")
    sh(k, "init", "-q", "-b", "main"); sh(k, "config", "user.name", "kb")
    sh(k, "config", "user.email", "kb@localhost"); sh(k, "add", "-A"); sh(k, "commit", "-q", "-m", "i")
    return k


def pkce():
    v = secrets.token_urlsafe(48)
    ch = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).decode().rstrip("=")
    return v, ch


def setup():
    tmp = tempfile.mkdtemp(prefix="brainy_oa_"); dbp = os.path.join(tmp, "brainy.db")
    conn = db.init_db(dbp)
    admin = acl.create_principal(conn, "USER", "admin", m.ADMIN)
    for kk in ("shared", "systems", "tools", "locked"):
        spaces.create_space(conn, admin["id"], kk, kk)
    account = acl.create_principal(conn, "AGENT", "claude-account", m.AGENT)
    worker = acl.create_principal(conn, "AGENT", "claude", m.AGENT)   # Legacy Service-Worker
    # claude-account ACL: Knowledge read/write + Task read/write (NICHT auf 'locked')
    acl.grant_permission(conn, admin["id"], "shared", account["id"], can_read=1, can_write=1,
                         can_create_tasks=1, can_claim_tasks=1, can_complete_tasks=1)
    acl.grant_permission(conn, admin["id"], "systems", account["id"], can_read=1)
    acl.grant_permission(conn, admin["id"], "tools", account["id"], can_read=1, can_write=1)
    acl.grant_permission(conn, admin["id"], "shared", worker["id"], can_read=1,
                         can_create_tasks=1, can_claim_tasks=1, can_complete_tasks=1)
    legacy_tok = tokens.create_service_token(conn, worker["id"])["token"]
    conn.close()
    svc = service.BrainyService(dbp, mini_kb(), rate_limit="100000/60")
    app = web.BrainyWeb(svc, SECRET)
    return svc, app, dbp, admin["id"], legacy_tok


svc, app, dbp, ADMIN, LEGACY = setup()
BASE = None  # config.PUBLIC_BASE_URL


def oauth_api(method, path, body=b"", query=""):
    return svc.handle_oauth(method, path, query, body)


def jbody(res):
    return json.loads(res[3].decode())


def loc(res):
    for k, v in res[2]:
        if k.lower() == "location":
            return v
    return None


def ck(pid):
    return "%s=%s" % (web.COOKIE, web.make_session(SECRET, pid))


def csrf(pid):
    return web.csrf_token(SECRET, web.make_session(SECRET, pid))


# ===== A/B Discovery =====
prm = oauth_api("GET", "/.well-known/oauth-protected-resource")
prm_j = jbody(prm)
check("A protected-resource-metadata", prm[0] == 200 and prm_j["resource"].endswith("/mcp")
      and prm_j["authorization_servers"])
asm = oauth_api("GET", "/.well-known/oauth-authorization-server")
asm_j = jbody(asm)
check("B authorization-server-metadata (S256, none, endpoints)",
      asm[0] == 200 and asm_j["code_challenge_methods_supported"] == ["S256"]
      and asm_j["token_endpoint_auth_method" if False else "token_endpoint_auth_methods_supported"] == ["none"]
      and asm_j["authorization_endpoint"].endswith("/oauth/authorize")
      and asm_j["registration_endpoint"].endswith("/oauth/register"))

# ===== C DCR =====
REDIR = "https://claude.ai/api/mcp/auth_callback"
reg = oauth_api("POST", "/oauth/register",
                json.dumps({"client_name": "Claude", "redirect_uris": [REDIR]}).encode())
reg_j = jbody(reg)
CID = reg_j.get("client_id")
check("C DCR register -> 201 + client_id + redirect echo",
      reg[0] == 201 and CID and reg_j["redirect_uris"] == [REDIR]
      and reg_j["token_endpoint_auth_method"] == "none")
check("S DCR ohne redirect_uris -> 400",
      oauth_api("POST", "/oauth/register", json.dumps({"client_name": "x"}).encode())[0] == 400)


def authorize_and_code(client_id, redirect_uri, scope, challenge, state="st123", decision="approve",
                       cookie=None):
    q = urllib.parse.urlencode({"client_id": client_id, "redirect_uri": redirect_uri,
                                "response_type": "code", "scope": scope, "state": state,
                                "code_challenge": challenge, "code_challenge_method": "S256"})
    cookie = cookie or ck(ADMIN)
    # Consent GET
    g = app.handle("GET", "/oauth/authorize", q, cookie, b"")
    # Consent POST (approve/deny) mit CSRF + allen Params
    form = {"csrf": csrf(ADMIN), "decision": decision, "client_id": client_id,
            "redirect_uri": redirect_uri, "response_type": "code", "scope": scope,
            "state": state, "code_challenge": challenge, "code_challenge_method": "S256"}
    p = app.handle("POST", "/oauth/authorize", "", cookie, urllib.parse.urlencode(form).encode())
    return g, p


# ===== D/I PKCE happy path =====
verifier, challenge = pkce()
g, p = authorize_and_code(CID, REDIR, "brainy:knowledge:read brainy:knowledge:write "
                          "brainy:tasks:read brainy:tasks:write", challenge)
check("Consent-GET 200 zeigt Client+Scopes", g[0] == 200 and b"Allow" in g[3])
redir = loc(p)
check("Consent-POST approve -> 303 redirect mit code+state",
      p[0] == 303 and redir and redir.startswith(REDIR) and "code=" in redir and "state=st123" in redir)
code = urllib.parse.parse_qs(urllib.parse.urlparse(redir).query)["code"][0]
tok = oauth_api("POST", "/oauth/token", urllib.parse.urlencode(
    {"grant_type": "authorization_code", "code": code, "client_id": CID,
     "redirect_uri": REDIR, "code_verifier": verifier}).encode())
tok_j = jbody(tok)
AT = tok_j.get("access_token"); RT = tok_j.get("refresh_token")
check("D/I Token-Exchange -> access+refresh (Bearer)",
      tok[0] == 200 and AT and AT.startswith("brat_") and RT and RT.startswith("brrt_")
      and tok_j["token_type"] == "Bearer" and tok_j["expires_in"] > 0)


def _form_action(res):
    for k, v in res[2]:
        if k == "Content-Security-Policy":
            for d in v.split(";"):
                if d.strip().startswith("form-action"):
                    return d.strip()
    return ""


# ===== CSP: OAuth-Consent erlaubt exakte redirect-Origin, Admin bleibt streng =====
check("CSP consent: form-action 'self' + exakte Origin (claude.ai), kein Wildcard",
      _form_action(g) == "form-action 'self' https://claude.ai")
dash = app.handle("GET", "/admin/", "", ck(ADMIN), b"")
check("CSP admin: bleibt form-action 'self' (kein claude.ai)",
      _form_action(dash) == "form-action 'self'")
reg2 = json.loads(oauth_api("POST", "/oauth/register", json.dumps(
    {"client_name": "Other", "redirect_uris": ["https://example.com/cb"]}).encode())[3])
v3, ch3 = pkce()
g2, _p2 = authorize_and_code(reg2["client_id"], "https://example.com/cb",
                             "brainy:tasks:read", ch3, state="o2")
check("CSP consent anderer Client: nur dessen Origin (example.com), nicht claude.ai",
      _form_action(g2) == "form-action 'self' https://example.com")

# ===== E invalid redirect_uri (kein Redirect) =====
ge, pe = authorize_and_code(CID, "https://evil.example/cb", "brainy:tasks:read", challenge)
check("E invalid redirect_uri -> 400 (KEIN Open-Redirect)", ge[0] == 400 and pe[0] == 400)

# ===== F code reuse (eigener Code, damit Haupt-AT/RT unberuehrt bleiben) =====
vf, chf = pkce()
_, pf = authorize_and_code(CID, REDIR, "brainy:tasks:read", chf, state="sf")
codef = urllib.parse.parse_qs(urllib.parse.urlparse(loc(pf)).query)["code"][0]
tf1 = oauth_api("POST", "/oauth/token", urllib.parse.urlencode(
    {"grant_type": "authorization_code", "code": codef, "client_id": CID,
     "redirect_uri": REDIR, "code_verifier": vf}).encode())
atf = jbody(tf1).get("access_token")
tf2 = oauth_api("POST", "/oauth/token", urllib.parse.urlencode(
    {"grant_type": "authorization_code", "code": codef, "client_id": CID,
     "redirect_uri": REDIR, "code_verifier": vf}).encode())
cf = db.connect(dbp)
revoked = oauth.authenticate_access_token(cf, atf) is None
cf.close()
check("F code reuse -> invalid_grant + abgeleiteter Token widerrufen",
      tf1[0] == 200 and tf2[0] == 400 and jbody(tf2)["error"] == "invalid_grant" and revoked)

# ===== H wrong verifier =====
v2, ch2 = pkce()
_, p2 = authorize_and_code(CID, REDIR, "brainy:tasks:read", ch2, state="s2")
code2 = urllib.parse.parse_qs(urllib.parse.urlparse(loc(p2)).query)["code"][0]
bad = oauth_api("POST", "/oauth/token", urllib.parse.urlencode(
    {"grant_type": "authorization_code", "code": code2, "client_id": CID,
     "redirect_uri": REDIR, "code_verifier": "WRONG"}).encode())
check("H falscher PKCE-verifier -> invalid_grant", bad[0] == 400 and jbody(bad)["error"] == "invalid_grant")

# ===== G expired auth code =====
c = db.connect(dbp)
acct_id = acl.get_principal_by_name(c, "claude-account")["id"]
expcode = oauth.create_auth_code(c, CID, acct_id, REDIR, "brainy:tasks:read", ch2, ttl=-10)
c.close()
gexp = oauth_api("POST", "/oauth/token", urllib.parse.urlencode(
    {"grant_type": "authorization_code", "code": expcode, "client_id": CID,
     "redirect_uri": REDIR, "code_verifier": v2}).encode())
check("G abgelaufener code -> invalid_grant", gexp[0] == 400 and jbody(gexp)["error"] == "invalid_grant")

# ===== S malformed token request =====
mal = oauth_api("POST", "/oauth/token", urllib.parse.urlencode({"grant_type": "weird"}).encode())
check("S unsupported_grant_type", mal[0] == 400 and jbody(mal)["error"] == "unsupported_grant_type")


# ===== L OAuth token -> MCP =====
def mcp(method, token, params=None):
    msg = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        msg["params"] = params
    st, ctype, bod = svc.handle_mcp("POST", "Bearer " + token, json.dumps(msg).encode())
    return st, (json.loads(bod) if bod else {})


st, o = mcp("initialize", AT, {"protocolVersion": "2025-06-18", "capabilities": {}})
check("L OAuth-Token initialize 200", st == 200 and o["result"]["serverInfo"]["name"] == "brainy")
st, o = mcp("tools/list", AT)
names = {t["name"] for t in o["result"]["tools"]}
check("L tools/list: nur Knowledge+Task-Tools (kein Admin/Dispatcher/Governance)",
      "get_document" in names and "write_document" in names and "create_task" in names
      and not (names & {"pause_dispatcher", "enable_agent", "review_task", "approve_task",
                        "list_agents", "list_execution_jobs"}))


def call(token, name, args):
    st, ctype, bod = svc.handle_mcp("POST", "Bearer " + token, json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": name, "arguments": args}}).encode())
    r = json.loads(bod)["result"]
    txt = r["content"][0]["text"]
    try:
        return r.get("isError"), json.loads(txt)
    except Exception:
        return r.get("isError"), txt


err, doc = call(AT, "get_document", {"path": "systems/brainy.md"})
check("L get_document via OAuth (read+ACL ok)", err is False and "Brainy" in doc["content"])
err, res = call(AT, "create_task", {"space": "shared", "title": "[oauth] test",
                                    "execution_mode": "AUTO", "action_class": "INTERNAL_READ"})
check("L create_task via OAuth (tasks:write + ACL ok)", err is False and res.get("task_id"))

# ===== N ACL zusaetzlich zu Scope: 'locked' Space ohne ACL -> forbidden =====
err, res = call(AT, "create_task", {"space": "locked", "title": "x"})
check("N ACL greift trotz Scope (locked -> forbidden)", err is True and res.get("error") == "forbidden")

# ===== M Scope-Begrenzung: nur knowledge:read -> kein write, kein task =====
vr, chr_ = pkce()
_, pr = authorize_and_code(CID, REDIR, "brainy:knowledge:read", chr_, state="ro")
codero = urllib.parse.parse_qs(urllib.parse.urlparse(loc(pr)).query)["code"][0]
tro = jbody(oauth_api("POST", "/oauth/token", urllib.parse.urlencode(
    {"grant_type": "authorization_code", "code": codero, "client_id": CID,
     "redirect_uri": REDIR, "code_verifier": vr}).encode()))
ATRO = tro["access_token"]
st, o = mcp("tools/list", ATRO)
ronames = {t["name"] for t in o["result"]["tools"]}
check("M Scope knowledge:read -> nur Read-Tools sichtbar",
      "get_document" in ronames and "write_document" not in ronames and "create_task" not in ronames)
err, res = call(ATRO, "write_document", {"path": "shared/x.md", "content": "# x\n",
                                         "commit_message": "m"})
check("M write_document ohne Scope -> forbidden", err is True and res.get("error") == "forbidden")

# ===== K refresh + revoke =====
rf = jbody(oauth_api("POST", "/oauth/token", urllib.parse.urlencode(
    {"grant_type": "refresh_token", "refresh_token": RT, "client_id": CID}).encode()))
check("K refresh_token -> neues access", rf.get("access_token", "").startswith("brat_"))
c = db.connect(dbp)
oauth.revoke(c, AT)
check("K revoke access -> danach ungueltig", oauth.authenticate_access_token(c, AT) is None)
oauth.revoke(c, RT)
c.close()
rf2 = oauth_api("POST", "/oauth/token", urllib.parse.urlencode(
    {"grant_type": "refresh_token", "refresh_token": RT, "client_id": CID}).encode())
check("K revoke refresh -> refresh schlaegt fehl", rf2[0] == 400)

# ===== J access token expiry =====
c = db.connect(dbp)
exp_at = oauth._issue_token(c, "access", CID, acct_id, "brainy:tasks:read", -5); c.commit()
check("J abgelaufenes access token -> None", oauth.authenticate_access_token(c, exp_at) is None)
c.close()

# ===== O no auth -> 401 =====
st, ctype, bod = svc.handle_mcp("POST", None, json.dumps(
    {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode())
check("O no-auth -> 401", st == 401)

# ===== P Legacy Service-Token weiterhin PASS (Backward Compatibility) =====
st, o = mcp("tools/list", LEGACY)
lnames = {t["name"] for t in o["result"]["tools"]}
check("P Legacy Service-Token: volle Tool-Liste (keine Scope-Grenze)",
      st == 200 and "create_task" in lnames and "list_tasks" in lnames)
err, sp = call(LEGACY, "list_spaces", {})
check("P Legacy Service-Token tools/call ok", err is False and "spaces" in sp)

# ===== R consent deny + CSRF =====
_, pdeny = authorize_and_code(CID, REDIR, "brainy:tasks:read", ch2, state="dny", decision="deny")
check("R consent deny -> redirect error=access_denied",
      pdeny[0] == 303 and "error=access_denied" in loc(pdeny) and "state=dny" in loc(pdeny))
nocsrf = app.handle("POST", "/oauth/authorize", "", ck(ADMIN), urllib.parse.urlencode(
    {"decision": "approve", "client_id": CID, "redirect_uri": REDIR, "code_challenge": ch2,
     "code_challenge_method": "S256", "response_type": "code", "scope": "brainy:tasks:read"}).encode())
check("R consent POST ohne CSRF -> 403", nocsrf[0] == 403)
# non-admin darf nicht autorisieren
reader = None
c = db.connect(dbp)
rd = acl.create_principal(c, "USER", "reader", m.READER); c.close()
gr = app.handle("GET", "/oauth/authorize",
                urllib.parse.urlencode({"client_id": CID, "redirect_uri": REDIR,
                                        "response_type": "code", "code_challenge": ch2,
                                        "code_challenge_method": "S256"}), ck(rd["id"]), b"")
check("R nur ADMIN darf autorisieren (READER -> 403)", gr[0] == 403)

# ===== Q Token-/Secret-Leakage: nur Hash gespeichert, kein Klartext =====
c = db.connect(dbp)
rows = " ".join(str(dict(r)) for r in c.execute("SELECT * FROM oauth_tokens").fetchall())
arows = " ".join(str(dict(r)) for r in c.execute("SELECT * FROM audit_events").fetchall())
c.close()
check("Q kein Klartext-Token in oauth_tokens/audit",
      AT not in rows and RT not in rows and AT not in arows and RT not in arows
      and CID in rows)   # client_id (public) darf vorkommen

print("\nGESAMT: %d PASS, %d FAIL" % (_ok[0], _fail[0]))
sys.exit(0 if _fail[0] == 0 else 1)
