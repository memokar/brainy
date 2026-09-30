"""Auth-Smoke (Temp-DB, KEIN Netzwerkdienst, KEINE produktive DB):
Principal + Agent + Token -> Auth -> ACL Space A ok / Space B deny -> revoke ->
Audit. Danach Temp-Daten loeschen. Aufruf: python3 scripts/auth_smoke.py"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from brainy import (acl, audit, auth, capabilities as cap, db, models as m,  # noqa: E402
                    spaces, tokens)


def main():
    tmp = tempfile.mkdtemp(prefix="brainy_authsmoke_")
    try:
        conn = db.init_db(os.path.join(tmp, "brainy.db"))
        admin = acl.create_principal(conn, "USER", "smoke-admin", m.ADMIN)
        spaces.create_space(conn, admin["id"], "A", "A")
        spaces.create_space(conn, admin["id"], "B", "B")
        agent = acl.create_principal(conn, "AGENT", "smoke-agent", m.AGENT)
        acl.grant_permission(conn, admin["id"], "A", agent["id"],
                             can_read=1, can_claim_tasks=1, can_complete_tasks=1)
        print("1) admin + agent + space A/B angelegt")

        tk = tokens.create_service_token(conn, agent["id"], description="smoke")
        print("2) Token erzeugt (token_id", tk["token_id"], ") — Klartext einmalig")
        ctx = auth.authenticate_token(conn, tk["token"])
        print("3) auth ok -> principal", ctx.principal_id, "role", ctx.role,
              "allowed_spaces", ctx.allowed_spaces, "auth_method", ctx.auth_method)

        print("4) ACL A (claim):", cap.check(conn, ctx, cap.TASK_CLAIM, "A"),
              "| ACL B (claim):", cap.check(conn, ctx, cap.TASK_CLAIM, "B"))

        tokens.revoke_service_token(conn, tk["token_id"])
        try:
            auth.authenticate_token(conn, tk["token"]); print("5) FEHLER: revoked akzeptiert")
        except Exception as e:
            print("5) revoked Token abgelehnt:", type(e).__name__)

        acts = [e["action"] for e in audit.list_events(conn, limit=50)]
        print("6) Audit-Events:", sorted(set(acts)))
        conn.close()
        print("SMOKE OK — Temp geloescht, kein Netzdienst")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
