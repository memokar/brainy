"""DB initialisieren + optional Default-Spaces + Bootstrap-ADMIN anlegen.
Aufruf: python3 scripts/init_db.py [DB_PFAD] [--seed]
Default-Pfad: /var/lib/brainy/brainy.db (Verzeichnis muss beschreibbar sein)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from brainy import acl, db, models as m, spaces  # noqa: E402

DEFAULT_DB = "/var/lib/brainy/brainy.db"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    seed = "--seed" in sys.argv
    path = args[0] if args else DEFAULT_DB
    conn = db.init_db(path)
    print("DB ready:", path, "| schema_version", db.schema_version(conn))
    if seed:
        admin = conn.execute("SELECT id FROM principals WHERE role='ADMIN' LIMIT 1").fetchone()
        if not admin:
            a = acl.create_principal(conn, "human", "bootstrap-admin", m.ADMIN)
            admin_id = a["id"]
            print("Bootstrap ADMIN created: id", admin_id)
        else:
            admin_id = admin["id"]
        neu = spaces.seed_defaults(conn, admin_id)
        print("Default spaces created:", neu or "(all present)")
    conn.close()


if __name__ == "__main__":
    main()
