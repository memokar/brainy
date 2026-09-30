"""Named Capabilities (Phase C) -> Abbildung auf Rollen + Space-ACL-Spalten.

Space-scoped Capabilities: erfordern Rolle-Ceiling UND Space-ACL-Spalte UND aktiven
Space (ueber acl.check_permission). Admin-Capabilities: rein rollenbasiert (global).
Explizites Fehlen einer Freigabe wird NICHT durch die globale Rolle umgangen
(ausser ADMIN-Bypass laut Designmodell).
"""
from . import acl
from . import models as m
from .errors import PermissionDenied
from .util import pid

# Knowledge
KNOWLEDGE_READ = "knowledge.read"
KNOWLEDGE_SEARCH = "knowledge.search"
KNOWLEDGE_WRITE = "knowledge.write"
# Tasks
TASK_READ = "task.read"
TASK_CREATE = "task.create"
TASK_CLAIM = "task.claim"
TASK_COMPLETE = "task.complete"
TASK_MANAGE = "task.manage"
TASK_REVIEW = "task.review"        # Review-Gate (Phase O1)
TASK_APPROVE = "task.approve"      # Approval-Gate (Phase O1)
# Spaces
SPACE_READ = "space.read"
SPACE_MANAGE = "space.manage"
# Administration (global, rollenbasiert)
PRINCIPAL_MANAGE = "principal.manage"
TOKEN_MANAGE = "token.manage"
ACL_MANAGE = "acl.manage"
AUDIT_READ = "audit.read"

# space-scoped Capability -> ACL-Spalte
_CAP_COLUMN = {
    KNOWLEDGE_READ: m.CAP_READ,
    KNOWLEDGE_SEARCH: m.CAP_READ,
    KNOWLEDGE_WRITE: m.CAP_WRITE,
    TASK_READ: m.CAP_READ,
    TASK_CREATE: m.CAP_CREATE_TASKS,
    TASK_CLAIM: m.CAP_CLAIM,
    TASK_COMPLETE: m.CAP_COMPLETE,
    TASK_MANAGE: m.CAP_CREATE_TASKS,
    TASK_REVIEW: m.CAP_REVIEW,
    TASK_APPROVE: m.CAP_APPROVE,
    SPACE_READ: m.CAP_READ,
    SPACE_MANAGE: m.CAP_MANAGE_SPACE,
}

# Admin-Capabilities -> erlaubte Rollen (global, kein Space)
_ADMIN_CAPS = {
    PRINCIPAL_MANAGE: {m.ADMIN},
    TOKEN_MANAGE: {m.ADMIN},
    ACL_MANAGE: {m.ADMIN},
    AUDIT_READ: {m.ADMIN, m.EDITOR},
}

ALL_CAPABILITIES = set(_CAP_COLUMN) | set(_ADMIN_CAPS)


def check(conn, principal, capability, space=None):
    p = acl.get_principal(conn, pid(principal))
    if not p or not p["active"]:
        return False
    if capability in _ADMIN_CAPS:
        return p["role"] == m.ADMIN or p["role"] in _ADMIN_CAPS[capability]
    col = _CAP_COLUMN.get(capability)
    if col is None:
        return False
    # Space-scoped -> delegiere an die Spalten-Pruefung (inkl. ADMIN-Bypass,
    # Rolle-Ceiling, Space-ACL und aktivem Space).
    if space is None:
        return False
    return acl.check_permission(conn, pid(principal), space, col)


def require(conn, principal, capability, space=None):
    if not check(conn, principal, capability, space):
        raise PermissionDenied(
            "principal %s: capability '%s' (space=%s) nicht erlaubt"
            % (pid(principal), capability, space))


def role_capabilities(role):
    """Menge der Named-Capabilities, die eine Rolle grundsaetzlich (mit passender
    ACL) ausueben kann — fuer Doku/Introspection."""
    caps = set()
    for cap, roles in _ADMIN_CAPS.items():
        if role == m.ADMIN or role in roles:
            caps.add(cap)
    for cap, col in _CAP_COLUMN.items():
        if role == m.ADMIN or col in m.ROLE_CAPS.get(role, set()):
            caps.add(cap)
    return caps
