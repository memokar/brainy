"""Brainy Phase-B Knowledge-Service Tests (A-R). Nur temporaere Test-Repos/DBs.
NICHT gegen produktive SoTs. Aufruf: python3 tests/test_knowledge.py"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from brainy import acl, audit, db, gitops, knowledge, models as m, spaces  # noqa: E402
from brainy.errors import Conflict, PermissionDenied, SecretDetected      # noqa: E402
from brainy.paths import PathNotAllowed                                   # noqa: E402

_ok = [0]
_fail = [0]


def check(label, cond, msg=""):
    if cond:
        _ok[0] += 1
        print("PASS " + label)
    else:
        _fail[0] += 1
        print("FAIL " + label + (": " + msg if msg else ""))


def raises(excs, fn, *a, **k):
    try:
        fn(*a, **k)
        return False
    except excs:
        return True
    except Exception:
        return False


def sh(root, *args):
    return subprocess.run(["git", "-C", root, *args], capture_output=True,
                          text=True).stdout


def fresh_kb():
    tmp = tempfile.mkdtemp(prefix="brainy_kb_")
    kroot = os.path.join(tmp, "kb")
    os.makedirs(kroot)
    for d in ("projects", "tools", "systems", "shared"):
        os.makedirs(os.path.join(kroot, d))
    def w(rel, txt):
        with open(os.path.join(kroot, rel), "w", encoding="utf-8") as fh:
            fh.write(txt)
    w("README.md", "# Brain Knowledge\n\nIndex.\n")
    w("tools/demo-bot.md", "# Demo-Bot\n\nPipeline. Token-Konzept beschrieben.\n")
    w("systems/brainy.md", "# Brainy\n\nBackbone.\n")
    w("shared/todo.md", "# TODO\n\n## Offen\n")
    w("tools/demo-bot.md.bak", "# ALT (Backup, darf NICHT gelistet werden)\n")
    for cmd in (["init", "-q", "-b", "main"], ["add", "-A"]):
        sh(kroot, *cmd)
    sh(kroot, "config", "user.name", "kb")
    sh(kroot, "config", "user.email", "kb@localhost")
    sh(kroot, "add", "-A")
    sh(kroot, "commit", "-q", "-m", "init")
    head = gitops.head_commit(kroot)

    conn = db.init_db(os.path.join(tmp, "brainy.db"))
    admin = acl.create_principal(conn, "human", "admin", m.ADMIN)
    for key, name in [("projects", "P"), ("tools", "T"), ("systems", "S"), ("shared", "Sh")]:
        spaces.create_space(conn, admin["id"], key, name)
    editor = acl.create_principal(conn, "human", "editor", m.EDITOR)
    reader = acl.create_principal(conn, "human", "reader", m.READER)
    agent = acl.create_principal(conn, "agent", "agent1", m.AGENT)
    acl.set_space_acl(conn, admin["id"], "tools", editor["id"], can_read=1, can_write=1)
    acl.set_space_acl(conn, admin["id"], "shared", editor["id"], can_read=1, can_write=1)
    acl.set_space_acl(conn, admin["id"], "systems", editor["id"], can_read=1, can_write=1)
    acl.set_space_acl(conn, admin["id"], "tools", reader["id"], can_read=1)
    acl.set_space_acl(conn, admin["id"], "tools", agent["id"], can_read=1)  # KEIN write
    return kroot, conn, dict(admin=admin, editor=editor, reader=reader, agent=agent), head


# A / B: listen
kroot, conn, P, head = fresh_kb()
docs = knowledge.list_documents(conn, P["editor"]["id"], root=kroot)
paths_listed = {d["path"] for d in docs}
check("A kanonische Dokumente gelistet",
      {"tools/demo-bot.md", "systems/brainy.md", "README.md", "shared/todo.md"} <= paths_listed
      or {"tools/demo-bot.md", "systems/brainy.md"} <= paths_listed, str(paths_listed))
check("B .bak nicht gelistet", "tools/demo-bot.md.bak" not in paths_listed)

# C: lesen
doc = knowledge.get_document(conn, P["reader"]["id"], "tools/demo-bot.md", root=kroot)
check("C Dokument lesen", "Demo-Bot" in doc["content"] and doc["git_commit"] == head)

# D: Path Traversal
check("D Traversal abgelehnt",
      raises(PathNotAllowed, knowledge.get_document, conn, P["reader"]["id"],
             "../../etc/passwd", root=kroot))

# E: Symlink-Escape (eigenes Repo, damit der untracked Symlink A-L nicht verunreinigt)
kroot_e, conn_e, P_e, head_e = fresh_kb()
try:
    os.symlink("/etc/hostname", os.path.join(kroot_e, "shared", "escape.md"))
    made = True
except OSError:
    made = False
if made:
    check("E Symlink-Escape abgelehnt",
          raises(PathNotAllowed, knowledge.get_document, conn_e, P_e["editor"]["id"],
                 "shared/escape.md", root=kroot_e))
else:
    print("SKIP E (kein Symlink-Support hier)")

# F: .git-Zugriff
check("F .git/ Zugriff abgelehnt",
      raises(PathNotAllowed, knowledge.get_document, conn, P["editor"]["id"],
             ".git/config", root=kroot))

# G / H: Suche + Space-Filter
hits = knowledge.search_knowledge(conn, P["editor"]["id"], "demo-bot", root=kroot)
check("G Suche liefert Treffer", any(h["path"] == "tools/demo-bot.md" for h in hits))
hits_shared = knowledge.search_knowledge(conn, P["editor"]["id"], "demo-bot",
                                         space="shared", root=kroot)
check("H Space-Filter", all(h["space"] == "shared" for h in hits_shared)
      and not any(h["path"] == "tools/demo-bot.md" for h in hits_shared))

# I: READER/AGENT darf nicht schreiben
check("I1 READER kein Write",
      raises(PermissionDenied, knowledge.write_document, conn, P["reader"]["id"],
             "tools/demo-bot.md", "# x\n", head, "msg", root=kroot))
check("I2 AGENT kein Write (Rolle ohne can_write)",
      raises(PermissionDenied, knowledge.write_document, conn, P["agent"]["id"],
             "tools/demo-bot.md", "# x\n", head, "msg", root=kroot))

# J / K / L: EDITOR-Write, genau 1 Commit, nur Ziel-Datei
n_before = int(sh(kroot, "rev-list", "--count", "HEAD").strip())
res = knowledge.write_document(conn, P["editor"]["id"], "tools/demo-bot.md",
                               "# Demo-Bot\n\nAktualisiert. Token-Konzept.\n",
                               head, "update demo-bot", root=kroot)
n_after = int(sh(kroot, "rev-list", "--count", "HEAD").strip())
check("J EDITOR-Write ok", bool(res["commit"]) and
      "Aktualisiert" in open(os.path.join(kroot, "tools/demo-bot.md"), encoding="utf-8").read())
check("K genau ein neuer Commit", n_after == n_before + 1, "%d->%d" % (n_before, n_after))
files = [x for x in sh(kroot, "show", "--name-only", "--pretty=format:", res["commit"]).split()
         if x]
check("L nur Ziel-Datei im Commit", files == ["tools/demo-bot.md"], str(files))

# M: veralteter expected_git_commit
kroot, conn, P, head = fresh_kb()
check("M stale expected_git_commit abgelehnt",
      raises(Conflict, knowledge.write_document, conn, P["editor"]["id"],
             "tools/demo-bot.md", "# x neu\n", "0000000000000000000000000000000000000000",
             "msg", root=kroot))

# N: Secret-Write abgelehnt
secret_body = "# Doc\n\n-----BEGIN OPENSSH PRIVATE KEY-----\nabcXYZ\n-----END-----\n"
check("N Secret-Write abgelehnt",
      raises(SecretDetected, knowledge.write_document, conn, P["editor"]["id"],
             "tools/demo-bot.md", secret_body, head, "msg", root=kroot))
check("N2 Datei nach Secret-Reject unveraendert + Repo clean",
      "PRIVATE KEY" not in open(os.path.join(kroot, "tools/demo-bot.md"), encoding="utf-8").read()
      and gitops.is_clean(kroot))

# O: Commit-Fehler -> Rollback
kroot, conn, P, head = fresh_kb()
orig = open(os.path.join(kroot, "tools/demo-bot.md"), encoding="utf-8").read()
_real = knowledge.gitops.commit_path
knowledge.gitops.commit_path = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
try:
    threw = raises(RuntimeError, knowledge.write_document, conn, P["editor"]["id"],
                   "tools/demo-bot.md", "# kaputt\n", head, "msg", root=kroot)
finally:
    knowledge.gitops.commit_path = _real
now = open(os.path.join(kroot, "tools/demo-bot.md"), encoding="utf-8").read()
check("O Commit-Fehler -> Datei zurueckgerollt + Repo clean",
      threw and now == orig and gitops.is_clean(kroot))

# P: fremde uncommitted Aenderung -> Write abgelehnt
kroot, conn, P, head = fresh_kb()
with open(os.path.join(kroot, "systems/brainy.md"), "a", encoding="utf-8") as fh:
    fh.write("\nfremde Aenderung\n")
check("P fremde uncommitted Aenderung -> Write abgelehnt",
      raises(Conflict, knowledge.write_document, conn, P["editor"]["id"],
             "tools/demo-bot.md", "# x\n", head, "msg", root=kroot))

# Q: Audit-Events
kroot, conn, P, head = fresh_kb()
knowledge.get_document(conn, P["reader"]["id"], "tools/demo-bot.md", root=kroot)
knowledge.search_knowledge(conn, P["reader"]["id"], "demo-bot", root=kroot)
r2 = knowledge.write_document(conn, P["editor"]["id"], "tools/demo-bot.md",
                             "# Demo-Bot v2\n", head, "v2", root=kroot)
raises(SecretDetected, knowledge.write_document, conn, P["editor"]["id"],
       "tools/demo-bot.md", "api_key = \"AKIAABCDEFGHIJKLMNOP\"\n",  # gitleaks:allow (fake key, tests the secret guard)
       r2["commit"], "sek", root=kroot)
acts = {e["action"] for e in audit.list_events(conn, object_type="knowledge", limit=100)}
check("Q Audit-Events korrekt",
      {"knowledge_read", "knowledge_search", "knowledge_write_committed",
       "knowledge_write_rejected_secret"} <= acts, str(acts))

# R: History
hist = knowledge.get_document_history(conn, P["editor"]["id"], "tools/demo-bot.md",
                                      limit=10, root=kroot)
check("R History funktioniert", len(hist) >= 2 and all("commit" in h for h in hist))

print("\nGESAMT: %d PASS, %d FAIL" % (_ok[0], _fail[0]))
sys.exit(0 if _fail[0] == 0 else 1)
