"""SQLite-Verbindung + Migrations. WAL + Foreign Keys aktiv."""
import glob
import os
import sqlite3

from .util import now_iso

MIGRATIONS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "migrations")


def connect(path):
    """Oeffnet eine Verbindung mit den verbindlichen PRAGMAs."""
    conn = sqlite3.connect(path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _applied_versions(conn):
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations "
        "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    conn.commit()
    return {r["version"] for r in conn.execute("SELECT version FROM schema_migrations")}


def migrate(conn, migrations_dir=None):
    """Wendet alle noch nicht angewandten *.sql-Migrationen in Reihenfolge an."""
    migrations_dir = migrations_dir or MIGRATIONS_DIR
    applied = _applied_versions(conn)
    files = sorted(glob.glob(os.path.join(migrations_dir, "*.sql")))
    neu = []
    for f in files:
        base = os.path.basename(f)
        try:
            version = int(base.split("_", 1)[0])
        except ValueError:
            continue
        if version in applied:
            continue
        with open(f, "r", encoding="utf-8") as fh:
            conn.executescript(fh.read())
        conn.execute("INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)",
                     (version, now_iso()))
        conn.commit()
        neu.append(version)
    return neu


def init_db(path, migrations_dir=None):
    """Erzeugt/oeffnet die DB (Verzeichnis wird angelegt) und migriert."""
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)
    conn = connect(path)
    migrate(conn, migrations_dir)
    return conn


def schema_version(conn):
    row = conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
    return (row["v"] if row else None) or 0
