"""Initialisiert die PRODUKTIVE Brainy-DB (Migrationen + Default-Spaces).
- KEIN automatisch generiertes Service-Token.
- Bootstrap-ADMIN nur, wenn der Principal-Store leer ist (technisch noetig, um
  Spaces zu seeden) — OHNE Token/Secret.
Aufruf: python3 scripts/init_prod_db.py [DB_PFAD]"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from brainy import auth, config, db, spaces  # noqa: E402


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    path = args[0] if args else config.DB_PATH
    conn = db.init_db(path)
    n = conn.execute("SELECT COUNT(*) AS c FROM principals").fetchone()["c"]
    if n == 0:
        auth.bootstrap_admin(conn, name="bootstrap-admin", with_token=False)  # KEIN Token
        print("Bootstrap-ADMIN angelegt (ohne Token).")
    admin = conn.execute("SELECT id FROM principals WHERE role='ADMIN' LIMIT 1").fetchone()
    neu = spaces.seed_defaults(conn, admin["id"])
    ntok = conn.execute("SELECT COUNT(*) AS c FROM service_tokens").fetchone()["c"]
    print("DB:", path, "| schema_version", db.schema_version(conn))
    print("Default-Spaces angelegt:", neu or "(alle vorhanden)")
    print("Service-Tokens:", ntok, "(soll 0)")
    conn.close()


if __name__ == "__main__":
    main()
