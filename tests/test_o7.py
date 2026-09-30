"""Brainy O7 Tests (Brainy-first + Selective Auto-Capture). Mechanik/Policy-Ebene:
Instructions-Auslieferung, Worker read-only, ACL/Secret-Guard beim Schreiben.
Verhaltensregeln (wann Claude schreibt) sind Instruction-getrieben und werden im realen
Smoke geprueft. Aufruf: python3 tests/test_o7.py"""
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from brainy import (acl, config, db, knowledge, models as m, service, spaces,  # noqa: E402
                    tokens)
from brainy.errors import PermissionDenied, SecretDetected  # noqa: E402

_ok = [0]; _fail = [0]


def check(label, cond, msg=""):
    if cond:
        _ok[0] += 1; print("PASS " + label)
    else:
        _fail[0] += 1; print("FAIL " + label + (": " + msg if msg else ""))


def sh(root, *a):
    return subprocess.run(["git", "-C", root, *a], capture_output=True, text=True).stdout


def mini_kb():
    tmp = tempfile.mkdtemp(prefix="brainy_o7kb_"); k = os.path.join(tmp, "kb"); os.makedirs(k)
    for d in ("projects", "tools", "systems", "shared"):
        os.makedirs(os.path.join(k, d))
    open(os.path.join(k, "systems", "brainy.md"), "w").write("# Brainy\n")
    sh(k, "init", "-q", "-b", "main"); sh(k, "config", "user.name", "kb")
    sh(k, "config", "user.email", "kb@localhost"); sh(k, "add", "-A"); sh(k, "commit", "-q", "-m", "i")
    return k


# ===== 1. Instructions-Policy wird ueber MCP initialize ausgeliefert =====
INS = service.MCP_INSTRUCTIONS
for marker in ("BRAINY-FIRST", "AUTO-CAPTURE", "NICHT automatisch speichern", "TRANSPARENZ",
               "Secrets/Tokens", "hypothetisch".upper() if False else "HYPOTHETISCHES",
               "conventions.md", "Single Source of Truth"):
    check("Instructions enthaelt: %s" % marker, marker in INS)

tmp = tempfile.mkdtemp(prefix="brainy_o7_"); dbp = os.path.join(tmp, "brainy.db")
conn = db.init_db(dbp)
admin = acl.create_principal(conn, "USER", "admin", m.ADMIN)
for kk in ("systems", "shared"):
    spaces.create_space(conn, admin["id"], kk, kk)
account = acl.create_principal(conn, "AGENT", "claude-account", m.AGENT)
acl.grant_permission(conn, admin["id"], "shared", account["id"], can_read=1, can_write=1)
acl.grant_permission(conn, admin["id"], "systems", account["id"], can_read=1)   # NUR read
tok = tokens.create_service_token(conn, account["id"])["token"]
conn.close()
svc = service.BrainyService(dbp, mini_kb(), rate_limit="100000/60")

st, ct, body = svc.handle_mcp("POST", "Bearer " + tok, json.dumps(
    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
     "params": {"protocolVersion": "2025-06-18", "capabilities": {}}}).encode())
ins = json.loads(body)["result"].get("instructions", "")
check("MCP initialize liefert die Brainy-first-Instructions", "BRAINY-FIRST" in ins and ins == INS)

# ===== 3. Auto-Capture respektiert ACL (claude-account nur innerhalb ACL) =====
c = db.connect(dbp)
# shared: write erlaubt
res = knowledge.write_document(c, account["id"], "shared/o7-note.md",
                               "# O7 Note\n\nDauerhafte Entscheidung X.\n", None,
                               "o7 capture", root=svc.knowledge_root)
check("Auto-Capture write in erlaubtem Space (shared) -> ok", res.get("commit"))
# systems: nur read -> write verboten
denied = False
try:
    knowledge.write_document(c, account["id"], "systems/hack.md", "# x\n", None, "x",
                             root=svc.knowledge_root)
except PermissionDenied:
    denied = True
check("Auto-Capture write ausserhalb ACL (systems) -> PermissionDenied", denied)

# ===== 4. Secret-Guard: token-artige Inhalte werden NIE gespeichert =====
sec = False
try:
    knowledge.write_document(c, account["id"], "shared/leak.md",
                             "# k\n\ntoken = \"ghp_" + "A" * 30 + "\"\n", None, "leak",
                             root=svc.knowledge_root)
except SecretDetected:
    sec = True
check("Secret-Guard blockt token-artigen Auto-Capture", sec)
check("scan_secrets: Token erkannt, Normaltext nicht",
      knowledge.scan_secrets("password = \"supersecret1234\"") is not None
      and knowledge.scan_secrets("Eine ganz normale Notiz ohne Secrets.") is None)
c.close()

print("\nGESAMT: %d PASS, %d FAIL" % (_ok[0], _fail[0]))
sys.exit(0 if _fail[0] == 0 else 1)
