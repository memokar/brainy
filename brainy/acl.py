"""Principals + Space-ACL + check_permission (Spalten-basiert, Phase A/B).

Effektives Recht (Nicht-ADMIN) = Rolle erlaubt Capability UND Space-ACL gewaehrt sie
UND Space ist aktiv. Ohne ACL-Zeile -> kein Zugriff. ADMIN global (bypass).
Named-Capabilities (knowledge.read, task.claim, ...) siehe capabilities.py.
"""
import sqlite3

from . import audit
from . import models as m
from .errors import BrainyError, NotFound, PermissionDenied
from .util import dumps, now_iso, pid


# ----- Principals -----
def create_principal(conn, principal_type, name, role, active=1, actor="system",
                     metadata=None):
    ptype = m.normalize_ptype(principal_type)
    if ptype is None:
        raise BrainyError("invalid principal_type: %s" % principal_type)
    if role not in m.ROLES:
        raise BrainyError("unknown role: %s" % role)
    now = now_iso()
    try:
        conn.execute(
            "INSERT INTO principals(principal_type, name, role, active, created_at, "
            "updated_at, metadata) VALUES(?, ?, ?, ?, ?, ?, ?)",
            (ptype, name, role, 1 if active else 0, now, now, dumps(metadata)),
        )
    except sqlite3.IntegrityError:
        raise BrainyError("principal already exists: %s" % name)
    row = conn.execute("SELECT id FROM principals WHERE name=?", (name,)).fetchone()
    audit.log(conn, actor, "principal_created", "principal", row["id"], None,
              {"role": role, "type": ptype})
    conn.commit()
    return get_principal(conn, row["id"])


def get_principal(conn, principal_id):
    r = conn.execute("SELECT * FROM principals WHERE id=?", (pid(principal_id),)).fetchone()
    return dict(r) if r else None


def get_principal_by_name(conn, name):
    r = conn.execute("SELECT * FROM principals WHERE name=?", (str(name),)).fetchone()
    return dict(r) if r else None


def update_principal(conn, actor, principal_id, role=None, active=None, metadata=None):
    p = get_principal(conn, principal_id)
    if not p:
        raise NotFound("principal %s" % principal_id)
    if role is not None and role not in m.ROLES:
        raise BrainyError("unknown role: %s" % role)
    sets, args = [], []
    if role is not None:
        sets.append("role=?"); args.append(role)
    if active is not None:
        sets.append("active=?"); args.append(1 if active else 0)
    if metadata is not None:
        sets.append("metadata=?"); args.append(dumps(metadata))
    sets.append("updated_at=?"); args.append(now_iso())
    args.append(pid(principal_id))
    conn.execute("UPDATE principals SET %s WHERE id=?" % ", ".join(sets), args)
    audit.log(conn, actor, "principal_updated", "principal", pid(principal_id), None,
              {"role": role, "active": active})
    conn.commit()
    return get_principal(conn, principal_id)


def disable_principal(conn, actor, principal_id):
    conn.execute("UPDATE principals SET active=0, updated_at=? WHERE id=?",
                 (now_iso(), pid(principal_id)))
    audit.log(conn, actor, "principal_disabled", "principal", pid(principal_id), None, {})
    conn.commit()
    return get_principal(conn, principal_id)


# ----- Spaces (Hilfen) -----
def get_space_row(conn, space):
    if isinstance(space, int):
        r = conn.execute("SELECT * FROM spaces WHERE id=?", (space,)).fetchone()
    else:
        r = conn.execute("SELECT * FROM spaces WHERE key=?", (str(space),)).fetchone()
    return dict(r) if r else None


def _space_id(conn, space):
    sp = get_space_row(conn, space)
    if not sp:
        raise NotFound("space not found: %s" % space)
    return sp["id"]


# ----- Space-ACL -----
def set_space_acl(conn, admin_id, space, principal_id, actor=None, **caps):
    """Legt/aktualisiert die ACL-Zeile. Nur ADMIN darf ACLs setzen."""
    if not is_admin(conn, admin_id):
        raise PermissionDenied("only ADMIN may set ACLs")
    sid = _space_id(conn, space)
    principal_id = pid(principal_id)
    existed = conn.execute(
        "SELECT 1 FROM space_acl WHERE space_id=? AND principal_id=?",
        (sid, principal_id)).fetchone() is not None
    cols = {c: (1 if caps.get(c) else 0) for c in m.ALL_CAPS}
    now = now_iso()
    conn.execute(
        "INSERT INTO space_acl(space_id, principal_id, can_read, can_write, "
        "can_create_tasks, can_claim_tasks, can_complete_tasks, can_manage_space, "
        "can_review, can_approve, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(space_id, principal_id) DO UPDATE SET "
        "can_read=excluded.can_read, can_write=excluded.can_write, "
        "can_create_tasks=excluded.can_create_tasks, can_claim_tasks=excluded.can_claim_tasks, "
        "can_complete_tasks=excluded.can_complete_tasks, can_manage_space=excluded.can_manage_space, "
        "can_review=excluded.can_review, can_approve=excluded.can_approve, "
        "updated_at=excluded.updated_at",
        (sid, principal_id, cols[m.CAP_READ], cols[m.CAP_WRITE], cols[m.CAP_CREATE_TASKS],
         cols[m.CAP_CLAIM], cols[m.CAP_COMPLETE], cols[m.CAP_MANAGE_SPACE],
         cols[m.CAP_REVIEW], cols[m.CAP_APPROVE], now, now),
    )
    audit.log(conn, actor or admin_id, "acl_updated" if existed else "acl_granted",
              "space", sid, sid,
              {"principal_id": principal_id, "caps": {k: cols[k] for k in m.ALL_CAPS}})
    conn.commit()


# Alias fuer die Phase-C-Namenskonvention
grant_permission = set_space_acl


def get_space_acl(conn, space, principal_id):
    sid = _space_id(conn, space)
    r = conn.execute("SELECT * FROM space_acl WHERE space_id=? AND principal_id=?",
                     (sid, pid(principal_id))).fetchone()
    return dict(r) if r else None


get_acl = get_space_acl


def list_acl(conn, space):
    sid = _space_id(conn, space)
    return [dict(r) for r in conn.execute(
        "SELECT * FROM space_acl WHERE space_id=? ORDER BY principal_id", (sid,))]


def remove_acl(conn, admin_id, space, principal_id):
    if not is_admin(conn, admin_id):
        raise PermissionDenied("only ADMIN may remove ACLs")
    sid = _space_id(conn, space)
    conn.execute("DELETE FROM space_acl WHERE space_id=? AND principal_id=?",
                 (sid, pid(principal_id)))
    audit.log(conn, admin_id, "acl_removed", "space", sid, sid,
              {"principal_id": pid(principal_id)})
    conn.commit()


# ----- Berechtigung -----
def is_admin(conn, principal_id):
    p = get_principal(conn, principal_id)
    return bool(p and p["active"] and p["role"] == m.ADMIN)


def check_permission(conn, principal_id, space, capability):
    """Spalten-basierte Pruefung (can_read/can_write/...). Nicht-ADMIN: Rolle-Ceiling
    UND Space-ACL UND Space aktiv."""
    if capability not in m.ALL_CAPS:
        return False
    p = get_principal(conn, principal_id)
    if not p or not p["active"]:
        return False
    if p["role"] == m.ADMIN:
        return True
    if not m.role_allows(p["role"], capability):
        return False
    sp = get_space_row(conn, space)
    if not sp or not sp["active"]:
        return False
    acl = get_space_acl(conn, space, principal_id)
    if not acl:
        return False
    return bool(acl[capability])


def require(conn, principal_id, space, capability):
    if not check_permission(conn, principal_id, space, capability):
        raise PermissionDenied(
            "principal %s: '%s' not allowed in space %s" % (pid(principal_id), capability, space))
