"""Append-only Audit. NUR INSERT/SELECT (DB-Trigger erzwingen append-only).
NIEMALS Secrets/Token-Werte/vollstaendige Payloads in metadata schreiben."""
from .util import dumps, now_iso


def log(conn, actor, action, object_type=None, object_id=None, space_id=None,
        metadata=None, commit=False):
    """Schreibt ein Audit-Event in die laufende Transaktion (Default: kein eigener
    Commit -> das Business-Event committet gemeinsam). metadata wird als JSON abgelegt."""
    conn.execute(
        "INSERT INTO audit_events(timestamp, actor, action, object_type, object_id, "
        "space_id, metadata) VALUES(?, ?, ?, ?, ?, ?, ?)",
        (now_iso(), str(actor) if actor is not None else None, action,
         object_type, str(object_id) if object_id is not None else None,
         space_id, dumps(metadata)),
    )
    if commit:
        conn.commit()


def list_events(conn, object_type=None, object_id=None, action=None, actor=None,
                space_id=None, limit=200):
    sql = "SELECT * FROM audit_events WHERE 1=1"
    args = []
    if object_type:
        sql += " AND object_type=?"; args.append(object_type)
    if object_id is not None:
        sql += " AND object_id=?"; args.append(str(object_id))
    if action:
        sql += " AND action=?"; args.append(action)
    if actor is not None:
        sql += " AND actor=?"; args.append(str(actor))
    if space_id is not None:
        sql += " AND space_id=?"; args.append(space_id)
    sql += " ORDER BY id DESC LIMIT ?"; args.append(limit)
    return [dict(r) for r in conn.execute(sql, args)]


def count(conn, action=None):
    if action:
        return conn.execute("SELECT COUNT(*) c FROM audit_events WHERE action=?",
                            (action,)).fetchone()["c"]
    return conn.execute("SELECT COUNT(*) c FROM audit_events").fetchone()["c"]
