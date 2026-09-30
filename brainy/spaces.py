"""Spaces (logische Bereiche/Mandanten)."""
from . import acl
from . import audit
from .errors import NotFound, PermissionDenied
from .util import now_iso

# Initiale Spaces (Seed). Die vier Knowledge-Kategorien sind zugleich die ACL-Spaces
# des Knowledge-Service; weitere Spaces (Projekte/Teams/Kunden) legt der ADMIN an.
DEFAULT_SPACES = [
    ("projects", "Knowledge: projects"),
    ("tools", "Knowledge: tools"),
    ("systems", "Knowledge: systems"),
    ("shared", "Shared / Knowledge: shared"),
    ("team", "Team"),
    ("infra", "Infrastructure"),
    ("personal", "Personal"),
]


def create_space(conn, admin_id, key, name, description=""):
    """Nur ADMIN darf Spaces anlegen (globale Verwaltung)."""
    if not acl.is_admin(conn, admin_id):
        raise PermissionDenied("nur ADMIN darf Spaces anlegen")
    now = now_iso()
    conn.execute(
        "INSERT INTO spaces(key, name, description, active, created_at, updated_at) "
        "VALUES(?, ?, ?, 1, ?, ?)", (key, name, description, now, now))
    sid = conn.execute("SELECT id FROM spaces WHERE key=?", (key,)).fetchone()["id"]
    audit.log(conn, admin_id, "space_created", "space", sid, sid, {"key": key})
    conn.commit()
    return get_space(conn, key)


def get_space(conn, key_or_id):
    if isinstance(key_or_id, int):
        r = conn.execute("SELECT * FROM spaces WHERE id=?", (key_or_id,)).fetchone()
    else:
        r = conn.execute("SELECT * FROM spaces WHERE key=?", (str(key_or_id),)).fetchone()
    return dict(r) if r else None


def list_spaces(conn, only_active=True):
    sql = "SELECT * FROM spaces"
    if only_active:
        sql += " WHERE active=1"
    sql += " ORDER BY key"
    return [dict(r) for r in conn.execute(sql)]


def seed_defaults(conn, admin_id):
    """Legt fehlende Default-Spaces an (idempotent). Nur ADMIN."""
    angelegt = []
    for key, name in DEFAULT_SPACES:
        if not get_space(conn, key):
            create_space(conn, admin_id, key, name)
            angelegt.append(key)
    return angelegt
