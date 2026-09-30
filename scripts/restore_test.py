#!/usr/bin/env python3
"""Brainy Restore-Verifikation (Finalphase) — beweist Wiederherstellbarkeit, OHNE die
produktive DB/Knowledge zu ersetzen.

Ablauf:
  SQLite : neuestes Backup -> Temp -> PRAGMA integrity_check -> Schema/Migrations ->
           Counts (spaces/principals/tasks/audit) gegen laufende DB (read-only) ->
           Service-Layer-Smoke (Reads) auf Restore-DB.
  Knowledge: neuestes Bundle -> Temp-Clone -> git fsck -> HEAD == Prod-HEAD ->
             systems/brainy.md lesen -> Such-Smoke.
Temp-Daten werden entfernt. Exit 0 = PASS.
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from brainy import config, db, spaces, tasks  # noqa: E402
from scripts import backup  # noqa: E402

_fail = [0]


def check(label, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + label + ((" :: " + extra) if extra else ""))
    if not cond:
        _fail[0] += 1


def main():
    backup_root = os.environ.get("BRAINY_BACKUP_ROOT", "/var/backups/brainy")
    db_bak = backup.latest_backup(backup_root, "brainy-", ".db")
    kb_bak = backup.latest_backup(backup_root, "knowledge-", ".bundle")
    check("Neuestes SQLite-Backup gefunden", bool(db_bak), str(db_bak))
    check("Neuestes Knowledge-Bundle gefunden", bool(kb_bak), str(kb_bak))
    if not (db_bak and kb_bak):
        return 1

    tmp = tempfile.mkdtemp(prefix="brainy_restore_")
    try:
        # ---- SQLite Restore ----
        rdb = os.path.join(tmp, "brainy.db")
        shutil.copy2(db_bak, rdb)
        check("SQLite integrity_check == ok", backup.integrity_check(rdb) == "ok")
        rconn = db.connect(rdb)
        try:
            mig = rconn.execute("SELECT COUNT(*) c FROM schema_migrations").fetchone()["c"]
            check("Schema/Migrations vorhanden", mig >= 1, "migrations=%d" % mig)
        except Exception as e:
            check("Schema/Migrations vorhanden", False, str(e))
        # Counts vs. laufende Prod-DB (read-only)
        prod = backup.db_counts(config.DB_PATH)
        rest = backup.db_counts(rdb)
        for key in ("spaces", "principals", "tasks", "audit_events"):
            check("Restore-Count == Prod (%s)" % key, prod[key] == rest[key],
                  "prod=%s restore=%s" % (prod[key], rest[key]))
        # Service-Layer-Smoke (Reads) auf Restore-DB
        sp = spaces.list_spaces(rconn)
        tk = tasks.list_tasks(rconn, limit=5)
        check("Restore-DB Service-Smoke (Spaces lesbar)", len(sp) >= 1, "spaces=%d" % len(sp))
        check("Restore-DB Service-Smoke (Tasks lesbar)", isinstance(tk, list))
        rconn.close()

        # ---- Knowledge Restore ----
        rkb = os.path.join(tmp, "kb")
        head, _ = backup.restore_knowledge_bundle(kb_bak, rkb)   # inkl. git fsck
        prod_head = backup.knowledge_head(config.KNOWLEDGE_ROOT)
        check("git fsck ok + HEAD == Prod-HEAD", head == prod_head,
              "restore=%s prod=%s" % (head[:12], prod_head[:12]))
        bm = os.path.join(rkb, "systems", "brainy.md")
        check("systems/brainy.md im Restore lesbar", os.path.exists(bm))
        if os.path.exists(bm):
            with open(bm, encoding="utf-8") as fh:
                txt = fh.read()
            check("Such-Smoke (Restore-Knowledge enthaelt 'Brainy')", "Brainy" in txt)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\nRESTORE-TEST: %s (%d Fehler)" % ("PASS" if _fail[0] == 0 else "FAIL", _fail[0]))
    return 0 if _fail[0] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
