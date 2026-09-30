"""Bootstrap-ADMIN anlegen — NUR bei leerem Principal-Store.
Aufruf: python3 scripts/bootstrap.py <DB_PFAD> [--name NAME] [--with-token]
Das Klartext-Token wird NUR bei --with-token und NUR EINMAL auf stdout ausgegeben.
Kein Default-Passwort, kein fest eingebautes Token. In Phase C KEIN produktives Token."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from brainy import auth, db  # noqa: E402


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if not args:
        print("Nutzung: bootstrap.py <DB_PFAD> [--name NAME] [--with-token]")
        sys.exit(2)
    path = args[0]
    name = "bootstrap-admin"
    if "--name" in sys.argv:
        name = sys.argv[sys.argv.index("--name") + 1]
    with_token = "--with-token" in sys.argv
    conn = db.init_db(path)
    res = auth.bootstrap_admin(conn, name=name, with_token=with_token)
    print("ADMIN angelegt: principal_id", res["principal_id"], "name", res["name"])
    if res["token"]:
        print("SERVICE-TOKEN (EINMALIG, sicher speichern):", res["token"])
    else:
        print("Kein Token erzeugt (--with-token nicht gesetzt).")
    conn.close()


if __name__ == "__main__":
    main()
