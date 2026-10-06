#!/usr/bin/env python3
"""Brainy Backup + Recovery-Helfer (stdlib-only).

Zwei persistente Datenklassen:
  A) Runtime-State  -> SQLite  (/var/lib/brainy/brainy.db)  : Online-Backup-API (.backup)
  B) Knowledge      -> Git-Repo (/opt/brainy-knowledge)      : `git bundle --all` (Offsite-faehig)

Eigenschaften:
- SQLite konsistent via sqlite3 Online-Backup-API (KEIN cp einer laufenden WAL-DB).
- Integritaetspruefung (PRAGMA integrity_check) vor der finalen, atomaren Ablage.
- Restriktive Rechte (0600) auf allen Backup-Artefakten; Backup-Dir 0700.
- Retention: 7 daily + 4 weekly je Datenklasse.
- Single-Run-Lock (flock) gegen parallele Laeufe. Exit!=0 bei Fehler.
- KEINE Secrets: /etc/brainy wird NICHT kopiert; nur ein Recovery-Manifest (nur Namen/
  Rechte, keine Werte). Externes verschluesseltes Offsite-Ziel bleibt bewusst offen.

CLI:
  backup.py run            # vollstaendiger Backup-Lauf (systemd-Timer)
  backup.py verify <db>    # PRAGMA integrity_check auf einer DB-Datei
"""
import glob
import os
import shutil
import sqlite3
import subprocess
import sys
import time


# --------------------------------------------------------------- SQLite
def backup_sqlite(db_path, dest_path):
    """Konsistentes Online-Backup nach dest_path (atomar via tmp+rename, 0600)."""
    tmp = dest_path + ".tmp"
    if os.path.exists(tmp):
        os.remove(tmp)
    # Quelle als normale Verbindung oeffnen: die Online-Backup-API liefert daraus einen
    # konsistenten Snapshot der laufenden (WAL-)DB. Es wird nur gelesen (backup()).
    src = sqlite3.connect(db_path, timeout=30)
    try:
        dst = sqlite3.connect(tmp)
        try:
            src.backup(dst)         # SQLite Online Backup API
            # Backup als self-contained Einzeldatei ablegen (WAL einfalten -> DELETE-Mode),
            # damit die Sicherung ohne -wal/-shm restore-faehig ist.
            dst.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            dst.execute("PRAGMA journal_mode=DELETE")
            dst.commit()
        finally:
            dst.close()
    finally:
        src.close()
    for ext in ("-wal", "-shm"):        # evtl. Sidecars der tmp-Verbindung entfernen
        side = tmp + ext
        if os.path.exists(side):
            os.remove(side)
    ok = integrity_check(tmp)
    if ok != "ok":
        os.remove(tmp)
        raise RuntimeError("integrity_check fehlgeschlagen: %s" % ok)
    os.chmod(tmp, 0o600)
    os.replace(tmp, dest_path)       # atomar
    return dest_path


def integrity_check(db_path):
    conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    try:
        row = conn.execute("PRAGMA integrity_check").fetchone()
        return row[0] if row else "no-result"
    finally:
        conn.close()


def db_counts(db_path):
    """Wesentliche Zeilenzahlen (fuer Restore-Vergleich). Read-only."""
    conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    try:
        out = {}
        for t in ("spaces", "principals", "tasks", "audit_events",
                  "service_tokens", "space_acl"):
            try:
                out[t] = conn.execute("SELECT COUNT(*) FROM %s" % t).fetchone()[0]
            except sqlite3.Error:
                out[t] = None
        try:
            out["schema_migrations"] = conn.execute(
                "SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
        except sqlite3.Error:
            out["schema_migrations"] = None
        return out
    finally:
        conn.close()


# --------------------------------------------------------------- Knowledge (git)
def _git(root, *args):
    r = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("git %s: %s" % (" ".join(args), (r.stderr or r.stdout).strip()))
    return r.stdout


def backup_knowledge(repo_path, dest_bundle):
    """Vollstaendiges `git bundle --all` (enthaelt komplette Historie, offsite-faehig)."""
    tmp = dest_bundle + ".tmp"
    if os.path.exists(tmp):
        os.remove(tmp)
    _git(repo_path, "bundle", "create", tmp, "--all")
    # Verifizieren, dass das Bundle gueltig ist:
    _git(repo_path, "bundle", "verify", tmp)
    os.chmod(tmp, 0o600)
    os.replace(tmp, dest_bundle)
    return dest_bundle


def knowledge_head(repo_path):
    return _git(repo_path, "rev-parse", "HEAD").strip()


def restore_knowledge_bundle(bundle_path, dest_dir):
    """Klont ein Bundle in ein Wegwerf-Verzeichnis. Rueckgabe: (head, dest_dir)."""
    subprocess.run(["git", "clone", "-q", bundle_path, dest_dir],
                   capture_output=True, text=True, check=True)
    _git(dest_dir, "fsck", "--full")
    head = _git(dest_dir, "rev-parse", "HEAD").strip()
    return head, dest_dir


# --------------------------------------------------------------- Retention
def _prune(dirpath, prefix, keep):
    files = sorted(glob.glob(os.path.join(dirpath, prefix + "*")), reverse=True)
    removed = []
    for f in files[keep:]:
        os.remove(f)
        removed.append(os.path.basename(f))
    return removed


def _promote_weekly(daily_dir, weekly_dir, prefix, ext, keep=4):
    files = sorted(glob.glob(os.path.join(daily_dir, prefix + "*" + ext)), reverse=True)
    if not files:
        return None
    tag = time.strftime("%G-W%V")
    target = os.path.join(weekly_dir, "%s%s%s" % (prefix, tag, ext))
    promoted = None
    if not os.path.exists(target):
        shutil.copy2(files[0], target)
        os.chmod(target, 0o600)
        promoted = os.path.basename(target)
    _prune(weekly_dir, prefix, keep)
    return promoted


# --------------------------------------------------------------- Manifest
def write_manifest(backup_root, db_path, knowledge_root, secrets_dir, db_file, bundle_file):
    """Recovery-Manifest: NUR Namen/Rechte/Groessen, KEINE Secret-Werte."""
    lines = ["# Brainy recovery manifest (NO secret values)",
             "# generated: %s" % time.strftime("%Y-%m-%dT%H:%M:%S%z"),
             "",
             "runtime_db_source: %s" % db_path,
             "latest_db_backup: %s" % os.path.basename(db_file),
             "knowledge_repo: %s" % knowledge_root,
             "latest_knowledge_bundle: %s" % os.path.basename(bundle_file),
             "knowledge_head: %s" % knowledge_head(knowledge_root),
             "",
             "# Secrets (restore MANUALLY from encrypted offsite storage — NOT backed up here):"]
    if os.path.isdir(secrets_dir):
        for name in sorted(os.listdir(secrets_dir)):
            p = os.path.join(secrets_dir, name)
            if os.path.isfile(p):
                st = os.stat(p)
                lines.append("  %s : mode=%o size=%d (value NOT backed up)"
                             % (name, st.st_mode & 0o777, st.st_size))
    lines += ["",
              "# Further DR artifacts (backed up separately by the operator):",
              "  /etc/systemd/system/brainy.service",
              "  /etc/systemd/system/brainy-backup.{service,timer}",
              "  /etc/nginx/sites-available/brainy.example.com",
              "  /etc/letsencrypt/  (TLS; or re-issue via certbot)",
              "",
              "# IMPORTANT: A local git repo/backup alone is NOT disaster recovery.",
              "# The external/encrypted offsite target still needs to be configured.",
              ""]
    manifest = os.path.join(backup_root, "RECOVERY_MANIFEST.txt")
    tmp = manifest + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    os.chmod(tmp, 0o600)
    os.replace(tmp, manifest)
    return manifest


# --------------------------------------------------------------- Orchestrierung
def run_backup(db_path, knowledge_root, backup_root, secrets_dir="/etc/brainy",
               keep_daily=7, keep_weekly=4, log=print):
    daily = os.path.join(backup_root, "daily")
    weekly = os.path.join(backup_root, "weekly")
    tmp = os.path.join(backup_root, "tmp")
    for d in (backup_root, daily, weekly, tmp):
        os.makedirs(d, exist_ok=True)
        os.chmod(d, 0o700)
    ts = time.strftime("%Y%m%dT%H%M%S")
    db_file = backup_sqlite(db_path, os.path.join(daily, "brainy-%s.db" % ts))
    log("sqlite-backup OK: %s (%d bytes)" % (os.path.basename(db_file),
                                             os.path.getsize(db_file)))
    bundle_file = backup_knowledge(knowledge_root,
                                   os.path.join(daily, "knowledge-%s.bundle" % ts))
    log("knowledge-bundle OK: %s (%d bytes)" % (os.path.basename(bundle_file),
                                                os.path.getsize(bundle_file)))
    # Retention
    _prune(daily, "brainy-", keep_daily)
    _prune(daily, "knowledge-", keep_daily)
    _promote_weekly(daily, weekly, "brainy-", ".db", keep_weekly)
    _promote_weekly(daily, weekly, "knowledge-", ".bundle", keep_weekly)
    manifest = write_manifest(backup_root, db_path, knowledge_root, secrets_dir,
                              db_file, bundle_file)
    log("manifest: %s" % os.path.basename(manifest))
    return {"db_file": db_file, "bundle_file": bundle_file, "manifest": manifest}


def latest_backup(backup_root, prefix, ext):
    for sub in ("daily", "weekly"):
        files = sorted(glob.glob(os.path.join(backup_root, sub, prefix + "*" + ext)),
                       reverse=True)
        if files:
            return files[0]
    return None


class _Lock:
    def __init__(self, path):
        self.path = path
        self.fd = None

    def __enter__(self):
        import fcntl
        self.fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self.fd)
            raise SystemExit("backup already running (lock held) -> aborting")
        return self

    def __exit__(self, *a):
        import fcntl
        try:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
        finally:
            os.close(self.fd)


def main(argv):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from brainy import config
    cmd = argv[1] if len(argv) > 1 else "run"
    if cmd == "verify":
        print(integrity_check(argv[2]))
        return 0
    if cmd == "run":
        backup_root = os.environ.get("BRAINY_BACKUP_ROOT", "/var/backups/brainy")
        os.makedirs(backup_root, exist_ok=True)
        os.chmod(backup_root, 0o700)
        with _Lock(os.path.join(backup_root, ".lock")):
            t0 = time.time()
            res = run_backup(config.DB_PATH, config.KNOWLEDGE_ROOT, backup_root)
            print("backup finished in %.1fs" % (time.time() - t0))
            return 0
    print("usage: backup.py [run|verify <db>]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
