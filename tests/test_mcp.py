"""Brainy MCP-Adapter Tests (JSON-RPC 2.0). svc.handle_mcp direkt (kein Socket).
Temp-DB/Test-Repo, KEIN produktiver Knowledge-Write. Aufruf: python3 tests/test_mcp.py"""
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from brainy import acl, audit, db, models as m, service, spaces, tokens  # noqa: E402

_ok = [0]; _fail = [0]


def check(label, cond, msg=""):
    if cond:
        _ok[0] += 1; print("PASS " + label)
    else:
        _fail[0] += 1; print("FAIL " + label + (": " + msg if msg else ""))


def sh(root, *a):
    return subprocess.run(["git", "-C", root, *a], capture_output=True, text=True).stdout


def mini_kb():
    tmp = tempfile.mkdtemp(prefix="brainy_mcpkb_"); k = os.path.join(tmp, "kb"); os.makedirs(k)
    for d in ("projects", "tools", "systems", "shared"):
        os.makedirs(os.path.join(k, d))
    open(os.path.join(k, "systems", "brainy.md"), "w").write("# Brainy\n\nBrainy backbone.\n")
    open(os.path.join(k, "tools", "x.md"), "w").write("# Tool X\n")
    sh(k, "init", "-q", "-b", "main"); sh(k, "config", "user.name", "kb")
    sh(k, "config", "user.email", "kb@localhost"); sh(k, "add", "-A"); sh(k, "commit", "-q", "-m", "init")
    return k


def setup():
    tmp = tempfile.mkdtemp(prefix="brainy_mcp_"); dbp = os.path.join(tmp, "brainy.db")
    conn = db.init_db(dbp)
    admin = acl.create_principal(conn, "USER", "admin", m.ADMIN)
    for kk in ("tools", "systems", "shared", "spaceB"):
        spaces.create_space(conn, admin["id"], kk, kk)
    claude = acl.create_principal(conn, "AGENT", "claude", m.AGENT)
    editor = acl.create_principal(conn, "USER", "editor", m.EDITOR)
    acl.grant_permission(conn, admin["id"], "tools", claude["id"], can_read=1)
    acl.grant_permission(conn, admin["id"], "systems", claude["id"], can_read=1)
    acl.grant_permission(conn, admin["id"], "shared", claude["id"],
                         can_read=1, can_create_tasks=1, can_claim_tasks=1, can_complete_tasks=1)
    acl.grant_permission(conn, admin["id"], "tools", editor["id"], can_read=1, can_write=1)
    tok = {"claude": tokens.create_service_token(conn, claude["id"])["token"],
           "editor": tokens.create_service_token(conn, editor["id"])["token"]}
    conn.close()
    svc = service.BrainyService(dbp, mini_kb(), rate_limit="10000/60")
    return svc, dbp, tok, claude["id"]


def rpc(svc, method, params=None, token=None, notif=False):
    msg = {"jsonrpc": "2.0", "method": method}
    if not notif:
        msg["id"] = 1
    if params is not None:
        msg["params"] = params
    hdr = ("Bearer " + token) if token else None
    st, ct, body = svc.handle_mcp("POST", hdr, json.dumps(msg).encode())
    return st, (json.loads(body) if body else {})


def call(svc, name, args, token):
    st, obj = rpc(svc, "tools/call", {"name": name, "arguments": args}, token)
    res = obj.get("result", {})
    txt = res.get("content", [{}])[0].get("text") if res.get("content") else None
    parsed = None
    try:
        parsed = json.loads(txt) if txt else None
    except Exception:
        parsed = txt
    return st, res.get("isError"), parsed


svc, dbp, TOK, claude_id = setup()

# initialize / handshake
st, o = rpc(svc, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}}, TOK["claude"])
check("initialize handshake", st == 200 and
      o["result"]["protocolVersion"] == service.MCP_PROTOCOL_VERSION and
      o["result"]["serverInfo"]["name"] == "brainy")

# notification -> 202 leer
stn, ctn, bn = svc.handle_mcp("POST", "Bearer " + TOK["claude"],
                              json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode())
check("notifications/initialized -> 202 leer", stn == 202 and bn == b"")

# Auth
check("invalid auth -> 401", rpc(svc, "tools/list", {}, "bk_x.WRONG")[0] == 401)
check("missing auth -> 401", rpc(svc, "tools/list", {}, None)[0] == 401)

# tools/list (claude: READ-ONLY Knowledge -> write-Tools versteckt)
st, o = rpc(svc, "tools/list", {}, TOK["claude"])
names = {t["name"] for t in o["result"]["tools"]}
check("tools/list valid auth", st == 200 and "list_spaces" in names and "claim_task" in names)
check("write-Tools fuer claude versteckt (read-only)",
      "write_document" not in names and "append_document" not in names)
# editor sieht write
oe = rpc(svc, "tools/list", {}, TOK["editor"])[1]
etools = {t["name"]: t for t in oe["result"]["tools"]}
check("write-Tool fuer EDITOR sichtbar", "write_document" in etools)
check("MCP-Annotations read-only/destructive korrekt",
      etools["get_document"]["annotations"]["readOnlyHint"] is True and
      etools["write_document"]["annotations"]["destructiveHint"] is True and
      etools["create_task"]["annotations"]["readOnlyHint"] is False)

# tool success (read)
st, err, spaces_res = call(svc, "list_spaces", {}, TOK["claude"])
check("tools/call list_spaces", st == 200 and err is False and "spaces" in spaces_res)
st, err, doc = call(svc, "get_document", {"path": "systems/brainy.md"}, TOK["claude"])
check("tools/call get_document", err is False and "Brainy" in doc["content"])
st, err, hits = call(svc, "search_knowledge", {"query": "brainy"}, TOK["claude"])
check("tools/call search_knowledge", err is False and hits["hits"])

# ACL deny (write ohne Recht) -> isError forbidden
st, err, res = call(svc, "write_document",
                    {"path": "systems/brainy.md", "content": "# x\n", "commit_message": "m"},
                    TOK["claude"])
check("ACL-Deny Write -> isError forbidden", err is True and res.get("error") == "forbidden")
# ACL deny: nicht erlaubter Space
st, err, res = call(svc, "list_tasks", {"space": "spaceB"}, TOK["claude"])
check("ACL-Deny fremder Space -> isError forbidden", err is True and res.get("error") == "forbidden")

# error mapping: path traversal
st, err, res = call(svc, "get_document", {"path": "../../etc/passwd"}, TOK["claude"])
check("error-mapping traversal -> invalid_request", err is True and res.get("error") == "invalid_request")

# Task-Roundtrip ueber MCP: create(READY) -> claim -> complete
st, err, t = call(svc, "create_task",
                  {"space": "shared", "title": "Brainy F2 MCP integration smoke",
                   "type": "chore", "status": "READY", "execution_mode": "AUTO", "action_class": "INTERNAL_READ"}, TOK["claude"])
check("roundtrip create_task", err is False and t.get("task_id"))
tid = t["task_id"]
st, err, c = call(svc, "claim_task", {"task_id": tid}, TOK["claude"])
check("roundtrip claim_task", err is False and c.get("claim_token"))
ctok = c["claim_token"]
# Doppel-Claim -> conflict
st, err, res = call(svc, "claim_task", {"task_id": tid}, TOK["claude"])
check("roundtrip Doppel-Claim -> conflict", err is True and res.get("error") == "conflict")
# stale token -> invalid_claim
st, err, res = call(svc, "complete_task", {"task_id": tid, "claim_token": "STALE"}, TOK["claude"])
check("roundtrip stale token -> invalid_claim", err is True and res.get("error") == "invalid_claim")
# complete
st, err, res = call(svc, "complete_task", {"task_id": tid, "claim_token": ctok, "result": "ok"},
                    TOK["claude"])
check("roundtrip complete_task", err is False)

# Verifikation im Core
tc = db.connect(dbp)
row = tc.execute("SELECT status, claimed_by FROM tasks WHERE task_id=?", (tid,)).fetchone()
check("Task COMPLETED + claimed_by=claude",
      row["status"] == "COMPLETED" and row["claimed_by"] == str(claude_id))

# kein Token-Leak im Audit
sec = TOK["claude"].split(".", 1)[1]
rows = tc.execute("SELECT actor,action,object_id,metadata FROM audit_events").fetchall()
leak = any(sec in " ".join(str(x) for x in r) for r in rows)
acts = {r["action"] for r in rows}
check("Audit: mcp-Events + auth_success, KEIN Token-Leak",
      not leak and "mcp_tool_called" in acts and "auth_success" in acts)

print("\nGESAMT: %d PASS, %d FAIL" % (_ok[0], _fail[0]))
sys.exit(0 if _fail[0] == 0 else 1)
