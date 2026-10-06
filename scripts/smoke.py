"""Lokaler CLI-Smoke-Test (kein Netzwerk): DB init -> Space -> Task -> READY ->
claim -> complete -> Audit anzeigen. Nutzt eine TEMP-DB, keine Produktivdaten.
Aufruf: python3 scripts/smoke.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from brainy import acl, audit, db, models as m, spaces, tasks  # noqa: E402


def main():
    tmp = tempfile.mkdtemp(prefix="brainy_smoke_")
    path = os.path.join(tmp, "brainy.db")
    conn = db.init_db(path)
    print("1) DB:", path, "schema", db.schema_version(conn))

    admin = acl.create_principal(conn, "human", "admin", m.ADMIN)
    agent = acl.create_principal(conn, "agent", "chatgpt", m.AGENT)
    spaces.create_space(conn, admin["id"], "demo-bot", "Demo-Bot")
    acl.set_space_acl(conn, admin["id"], "demo-bot", agent["id"],
                      can_read=1, can_create_tasks=1, can_claim_tasks=1, can_complete_tasks=1)
    print("2) space 'demo-bot' + AGENT 'chatgpt' with claim/complete permission")

    t = tasks.create_task(conn, agent["id"], "demo-bot", "Image for post X",
                          type="image", priority="P2", target_ref="demo-bot")
    print("3) task created:", t["task_id"], t["status"])
    tasks.set_status(conn, agent["id"], t["task_id"], m.READY)
    print("4) -> READY")
    c = tasks.claim_task(conn, agent["id"], t["task_id"])
    print("5) claimed, lease_until", c["lease_until"])
    tasks.complete_task(conn, agent["id"], t["task_id"], c["claim_token"],
                        result="ok", result_refs=[{"kind": "image", "id": "img_123"}])
    print("6) completed, status", tasks.get_task(conn, t["task_id"])["status"])

    print("7) Audit:")
    for e in reversed(audit.list_events(conn, object_id=t["task_id"])):
        print("   ", e["timestamp"], e["actor"], e["action"])
    conn.close()
    print("SMOKE OK")


if __name__ == "__main__":
    main()
