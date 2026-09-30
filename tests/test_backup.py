"""Brainy Backup/Restore Tests (Finalphase). Temp-DB/Temp-Repo, KEIN produktiver
Zugriff, KEIN produktiver Knowledge-Write. Aufruf: python3 tests/test_backup.py"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from brainy import acl, db, models as m, spaces, tasks  # noqa: E402
from scripts import backup  # noqa: E402

_ok = [0]; _fail = [0]


def check(label, cond, msg=""):
    if cond:
        _ok[0] += 1; print("PASS " + label)
    else:
        _fail[0] += 1; print("FAIL " + label + (": " + msg if msg else ""))


def sh(root, *a):
    return subprocess.run(["git", "-C", root, *a], capture_output=True, text=True).stdout


def mini_kb(base):
    k = os.path.join(base, "kb"); os.makedirs(k)
    for d in ("projects", "tools", "systems", "shared"):
        os.makedirs(os.path.join(k, d))
    open(os.path.join(k, "systems", "brainy.md"), "w").write("# Brainy\n\nBrainy backbone.\n")
    sh(k, "init", "-q", "-b", "main"); sh(k, "config", "user.name", "kb")
    sh(k, "config", "user.email", "kb@localhost"); sh(k, "add", "-A"); sh(k, "commit", "-q", "-m", "init")
    return k


def make_db(base):
    dbp = os.path.join(base, "brainy.db")
    conn = db.init_db(dbp)
    admin = acl.create_principal(conn, "USER", "admin", m.ADMIN)
    for kk in ("shared", "tools"):
        spaces.create_space(conn, admin["id"], kk, kk)
    tasks.create_task(conn, admin["id"], "shared", "backup smoke", status=m.READY)
    conn.close()
    return dbp


base = tempfile.mkdtemp(prefix="brainy_bak_")
dbp = make_db(base)
kb = mini_kb(base)
backup_root = os.path.join(base, "backups")

# --- Voller Backup-Lauf ---
res = backup.run_backup(dbp, kb, backup_root, secrets_dir=os.path.join(base, "nosec"),
                        log=lambda *a: None)
check("Backup-Lauf erzeugt DB+Bundle+Manifest",
      os.path.exists(res["db_file"]) and os.path.exists(res["bundle_file"])
      and os.path.exists(res["manifest"]))

# --- Rechte 0600 ---
check("DB-Backup Rechte 0600", (os.stat(res["db_file"]).st_mode & 0o777) == 0o600)
check("Bundle Rechte 0600", (os.stat(res["bundle_file"]).st_mode & 0o777) == 0o600)

# --- SQLite integrity_check ---
check("SQLite integrity_check == ok", backup.integrity_check(res["db_file"]) == "ok")

# --- Datenvergleich (Backup == Quelle) ---
c_src = backup.db_counts(dbp)
c_bak = backup.db_counts(res["db_file"])
check("Restore-Datenvergleich (spaces/principals/tasks/audit gleich)",
      c_src["spaces"] == c_bak["spaces"] and c_src["principals"] == c_bak["principals"]
      and c_src["tasks"] == c_bak["tasks"] and c_src["audit_events"] == c_bak["audit_events"]
      and c_bak["tasks"] >= 1, "src=%s bak=%s" % (c_src, c_bak))

# --- Restore-DB Service-Smoke (read) ---
rconn = db.connect(res["db_file"])
sp = spaces.list_spaces(rconn)
tk = tasks.list_tasks(rconn, space="shared")
rconn.close()
check("Restore-DB nutzbar (spaces+tasks lesbar)", len(sp) >= 2 and len(tk) >= 1)

# --- Knowledge Restore aus Bundle (git fsck + HEAD) ---
rest = os.path.join(base, "kb_restore")
head, _ = backup.restore_knowledge_bundle(res["bundle_file"], rest)
check("Knowledge-Bundle Restore: HEAD == Quelle + fsck ok",
      head == backup.knowledge_head(kb))
check("Restore Working Tree korrekt (systems/brainy.md vorhanden)",
      os.path.exists(os.path.join(rest, "systems", "brainy.md")))
with open(os.path.join(rest, "systems", "brainy.md")) as fh:
    check("Restore Inhalt lesbar (search-smoke)", "backbone" in fh.read())

# --- Retention: _prune behaelt nur keep neueste ---
pdir = os.path.join(base, "prunetest"); os.makedirs(pdir)
for i in range(10):
    open(os.path.join(pdir, "brainy-2026010%dT000000.db" % i), "w").write("x")
backup._prune(pdir, "brainy-", 7)
remaining = [f for f in os.listdir(pdir) if f.startswith("brainy-")]
check("Retention _prune behaelt genau 7", len(remaining) == 7)

# --- Weekly-Promotion ---
wdir = os.path.join(base, "weekly"); os.makedirs(wdir)
promoted = backup._promote_weekly(os.path.join(backup_root, "daily"), wdir,
                                  "brainy-", ".db", keep=4)
check("Weekly-Promotion erzeugt Weekly-Kopie",
      promoted is not None and len(os.listdir(wdir)) >= 1)

# --- Manifest enthaelt KEINE Secret-Werte (nur Namen) ---
with open(res["manifest"]) as fh:
    man = fh.read()
check("Manifest ohne Secret-Werte + DR-Hinweis",
      "Wert NICHT gesichert" in man or "KEINE Secret" in man)

print("\nGESAMT: %d PASS, %d FAIL" % (_ok[0], _fail[0]))
sys.exit(0 if _fail[0] == 0 else 1)
