"""Agent-Registry (Worker-Steuerung). Capabilities/Spaces werden aus der Principal-ACL
abgeleitet, NICHT dupliziert. KEINE Secrets/Token hier."""
from . import acl
from . import audit
from .errors import BrainyError, NotFound, PermissionDenied
from .util import now_iso, pid


def register_agent(conn, actor, agent_name, principal_id, worker_type, enabled=0,
                   max_concurrency=1, config_ref=None, status="registered"):
    p = acl.get_principal(conn, pid(principal_id))
    if not p:
        raise NotFound("principal %s" % principal_id)
    now = now_iso()
    conn.execute(
        "INSERT INTO agents(agent_name, principal_id, worker_type, enabled, max_concurrency, "
        "config_ref, status, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(agent_name) DO UPDATE SET worker_type=excluded.worker_type, "
        "max_concurrency=excluded.max_concurrency, config_ref=excluded.config_ref, "
        "updated_at=excluded.updated_at",
        (agent_name, p["id"], worker_type, 1 if enabled else 0, max_concurrency,
         config_ref, status, now, now))
    audit.log(conn, actor, "agent_registered", "agent", agent_name, None,
              {"worker_type": worker_type})
    conn.commit()
    return get_agent(conn, agent_name)


def get_agent(conn, agent_name):
    r = conn.execute(
        "SELECT a.*, p.name AS principal_name, p.role AS principal_role, p.active AS principal_active "
        "FROM agents a JOIN principals p ON p.id=a.principal_id WHERE a.agent_name=?",
        (agent_name,)).fetchone()
    return dict(r) if r else None


def list_agents(conn):
    return [dict(r) for r in conn.execute(
        "SELECT a.*, p.name AS principal_name, p.role AS principal_role, "
        "p.active AS principal_active FROM agents a JOIN principals p ON p.id=a.principal_id "
        "ORDER BY a.agent_name")]


def set_enabled(conn, actor, agent_name, on):
    """Nur ADMIN darf Agenten (de)aktivieren."""
    if not acl.is_admin(conn, pid(actor)):
        raise PermissionDenied("nur ADMIN darf Agenten schalten")
    if not get_agent(conn, agent_name):
        raise NotFound("agent %s" % agent_name)
    conn.execute("UPDATE agents SET enabled=?, updated_at=? WHERE agent_name=?",
                 (1 if on else 0, now_iso(), agent_name))
    audit.log(conn, actor, "agent_enabled" if on else "agent_disabled", "agent",
              agent_name, None, {})
    conn.commit()
    return get_agent(conn, agent_name)


def touch(conn, agent_name, status=None):
    if status is not None:
        conn.execute("UPDATE agents SET last_seen=?, status=?, updated_at=? WHERE agent_name=?",
                     (now_iso(), status, now_iso(), agent_name))
    else:
        conn.execute("UPDATE agents SET last_seen=?, updated_at=? WHERE agent_name=?",
                     (now_iso(), now_iso(), agent_name))
