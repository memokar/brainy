"""Brainy Write-Vorschlaege + Telegram-Freigabe (Approval-gated Knowledge-Writes).
Nur temporaere Test-Repos/DBs. Aufruf: python3 tests/test_proposals.py"""
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from brainy import acl, config, db, models as m, proposals, service, spaces, tokens  # noqa: E402
from brainy.errors import InvalidState, PermissionDenied, SecretDetected  # noqa: E402

_ok = [0]; _fail = [0]


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


def sh(root, *a):
    return subprocess.run(["git", "-C", root, *a], capture_output=True, text=True).stdout


def mini_kb():
    tmp = tempfile.mkdtemp(prefix="brainy_propkb_"); k = os.path.join(tmp, "kb"); os.makedirs(k)
    for d in ("projects", "tools", "systems", "shared"):
        os.makedirs(os.path.join(k, d))
    open(os.path.join(k, "systems", "brainy.md"), "w").write("# Brainy\n\nBackbone.\n")
    open(os.path.join(k, "tools", "x.md"), "w").write("# Tool X\n")
    sh(k, "init", "-q", "-b", "main"); sh(k, "config", "user.name", "kb")
    sh(k, "config", "user.email", "kb@localhost"); sh(k, "add", "-A")
    sh(k, "commit", "-q", "-m", "init")
    return k


def setup():
    tmp = tempfile.mkdtemp(prefix="brainy_prop_"); dbp = os.path.join(tmp, "brainy.db")
    conn = db.init_db(dbp)
    admin = acl.create_principal(conn, "USER", "admin", m.ADMIN)
    for kk in ("projects", "tools", "systems", "shared"):
        spaces.create_space(conn, admin["id"], kk, kk)
    chatgpt = acl.create_principal(conn, "AGENT", "chatgpt", m.AGENT)
    editor = acl.create_principal(conn, "USER", "editor", m.EDITOR)
    # ChatGPT: NUR Leserecht (kein can_write) auf allen Knowledge-Spaces
    for sp in ("projects", "tools", "systems", "shared"):
        acl.grant_permission(conn, admin["id"], sp, chatgpt["id"], can_read=1)
    # editor: read+approve auf systems (fuer Selbstfreigabe-Test)
    acl.grant_permission(conn, admin["id"], "systems", editor["id"],
                         can_read=1, can_write=1, can_approve=1)
    tok = {"chatgpt": tokens.create_service_token(conn, chatgpt["id"])["token"],
           "admin": tokens.create_service_token(conn, admin["id"])["token"]}
    ids = {"admin": admin["id"], "chatgpt": chatgpt["id"], "editor": editor["id"]}
    conn.close()
    svc = service.BrainyService(dbp, mini_kb(), rate_limit="10000/60")
    return svc, dbp, tok, ids


def call(svc, name, args, token):
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": name, "arguments": args}}
    st, ct, body = svc.handle_mcp("POST", "Bearer " + token, json.dumps(msg).encode())
    obj = json.loads(body) if body else {}
    res = obj.get("result", {})
    txt = res.get("content", [{}])[0].get("text") if res.get("content") else None
    try:
        parsed = json.loads(txt) if txt else None
    except Exception:
        parsed = txt
    return st, res.get("isError"), parsed


svc, dbp, TOK, IDS = setup()
kb = svc.knowledge_root


# --- 1) tools/list: propose_write sichtbar fuer ChatGPT (AGENT ohne write); write_document versteckt
msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
st, ct, body = svc.handle_mcp("POST", "Bearer " + TOK["chatgpt"], json.dumps(msg).encode())
names = {t["name"] for t in json.loads(body)["result"]["tools"]}
check("propose_write fuer ChatGPT sichtbar", "propose_write" in names)
check("write_document fuer ChatGPT weiterhin versteckt", "write_document" not in names)

# --- 2) MCP propose_write (ChatGPT, nur Leserecht) -> PENDING-Vorschlag
st, err, res = call(svc, "propose_write",
                    {"path": "systems/brainy.md",
                     "content": "# Brainy\n\nBackbone. Ergaenzt via Vorschlag.\n",
                     "commit_message": "ergaenze brainy.md"}, TOK["chatgpt"])
check("propose_write ok -> pending_approval",
      err is False and res.get("status") == "pending_approval" and res.get("proposal_id"))
pid1 = res.get("proposal_id")

# Datei noch UNVERAENDERT (nur Vorschlag, kein Write)
before = open(os.path.join(kb, "systems/brainy.md"), encoding="utf-8").read()
check("Datei nach Vorschlag unveraendert", "Ergaenzt via Vorschlag" not in before)

# --- 3) direkter create_proposal: ohne Leserecht -> PermissionDenied
conn = db.connect(dbp)
stranger = acl.create_principal(conn, "AGENT", "stranger", m.AGENT)  # keine ACL
check("Vorschlag ohne Leserecht im Space -> PermissionDenied",
      raises(PermissionDenied, proposals.create_proposal, conn, stranger["id"],
             "systems/brainy.md", "# x\n", "m", root=kb))

# --- 4) Secret im Vorschlag -> abgelehnt, KEINE Zeile gespeichert
n_before = conn.execute("SELECT COUNT(*) c FROM write_proposals").fetchone()["c"]
check("Secret-Vorschlag abgelehnt",
      raises(SecretDetected, proposals.create_proposal, conn, IDS["chatgpt"],
             "systems/brainy.md",
             "# x\n\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAA\n-----END-----\n",
             "sek", root=kb))
n_after = conn.execute("SELECT COUNT(*) c FROM write_proposals").fetchone()["c"]
check("Secret-Vorschlag nicht gespeichert", n_after == n_before)

# --- 5) apply durch Nicht-Approver (ChatGPT, AGENT) -> PermissionDenied
check("apply durch AGENT (kein approve) -> PermissionDenied",
      raises(PermissionDenied, proposals.apply_proposal, conn, IDS["chatgpt"], pid1, root=kb))

# --- 6) apply durch ADMIN -> echter Write + Git-Commit; Status APPLIED
res6 = proposals.apply_proposal(conn, IDS["admin"], pid1, root=kb)
after = open(os.path.join(kb, "systems/brainy.md"), encoding="utf-8").read()
check("apply durch ADMIN -> Datei geschrieben",
      res6["status"] == "APPLIED" and "Ergaenzt via Vorschlag" in after and res6["result_commit"])
# idempotent
res6b = proposals.apply_proposal(conn, IDS["admin"], pid1, root=kb)
check("apply idempotent (bereits APPLIED)", res6b["status"] == "APPLIED")

# --- 7) reject-Flow: neuer Vorschlag -> reject -> Datei unveraendert
p7 = proposals.create_proposal(conn, IDS["chatgpt"], "tools/x.md",
                              "# Tool X\n\nSOLLTE NICHT ERSCHEINEN\n", "boese", root=kb)
proposals.reject_proposal(conn, IDS["admin"], p7["proposal_id"], note="nein")
xcontent = open(os.path.join(kb, "tools/x.md"), encoding="utf-8").read()
check("reject -> Status REJECTED",
      proposals.get_proposal(conn, p7["proposal_id"])["status"] == "REJECTED")
check("reject -> Datei unveraendert", "SOLLTE NICHT ERSCHEINEN" not in xcontent)
# reject dann apply -> InvalidState
check("apply nach reject -> InvalidState",
      raises(InvalidState, proposals.apply_proposal, conn, IDS["admin"], p7["proposal_id"], root=kb))

# --- 8) Selbstfreigabe gesperrt: editor schlaegt vor + will selbst freigeben
p8 = proposals.create_proposal(conn, IDS["editor"], "systems/brainy.md",
                              "# Brainy\n\nEditor-Vorschlag.\n", "editor change", root=kb)
check("Selbstfreigabe (editor approves own) -> PermissionDenied",
      raises(PermissionDenied, proposals.apply_proposal, conn, IDS["editor"],
             p8["proposal_id"], root=kb))
# admin darf freigeben
r8 = proposals.apply_proposal(conn, IDS["admin"], p8["proposal_id"], root=kb)
check("admin gibt fremden Vorschlag frei", r8["status"] == "APPLIED")
conn.close()

# --- 9) Telegram-Webhook: Auth + Approve
config.TELEGRAM_WEBHOOK_SECRET = "s3cr3t"
config.TELEGRAM_OWNER_CHAT_ID = "999"
config.TELEGRAM_BOT_TOKEN = ""                       # kein Netzwerk
config.TELEGRAM_TOKEN_FILE = "/nonexistent/telegram_token"
config.TELEGRAM_APPROVER_PRINCIPAL = "admin"

# frischer PENDING-Vorschlag fuer den Webhook-Test
conn = db.connect(dbp)
pw = proposals.create_proposal(conn, IDS["chatgpt"], "tools/x.md",
                              "# Tool X\n\nvia Telegram freigegeben\n", "tg apply", root=kb)
conn.close()
pwid = pw["proposal_id"]


def tg(secret, from_id, action, proposal_id):
    upd = {"callback_query": {"id": "cq1", "from": {"id": from_id},
                              "message": {"chat": {"id": from_id}, "message_id": 5},
                              "data": "%s:%s" % (action, proposal_id)}}
    return svc.handle_telegram("POST", secret, json.dumps(upd).encode())

# falscher secret_token -> 401
st, _, _ = tg("WRONG", 999, "ap", pwid)
check("Telegram falscher secret_token -> 401", st == 401)
# richtiger secret, aber falsche Chat-ID -> 200, aber NICHT angewendet
st, _, _ = tg("s3cr3t", 111, "ap", pwid)
c2 = db.connect(dbp)
still_pending = proposals.get_proposal(c2, pwid)["status"] == "PENDING"
c2.close()
check("Telegram fremde Chat-ID gibt NICHT frei", st == 200 and still_pending)
# richtiger secret + Owner + approve -> angewendet
st, _, _ = tg("s3cr3t", 999, "ap", pwid)
c3 = db.connect(dbp)
applied = proposals.get_proposal(c3, pwid)["status"] == "APPLIED"
c3.close()
xc = open(os.path.join(kb, "tools/x.md"), encoding="utf-8").read()
check("Telegram Owner-Approve -> APPLIED + Datei geschrieben",
      st == 200 and applied and "via Telegram freigegeben" in xc)

print("\nGESAMT: %d PASS, %d FAIL" % (_ok[0], _fail[0]))
sys.exit(0 if _fail[0] == 0 else 1)
