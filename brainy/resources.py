"""Brainy Resource Claims (Phase B, 0.2.0).

Befristete, exklusive Reservierung beliebiger Ressourcen - ein freier String-Key je Space
(z.B. "repo:app/src/auth/**", "deploy:staging"). Gleiches Prinzip wie Task-Claims:

- atomarer Claim (genau EIN gleichzeitiger Claimer gewinnt),
- Lease mit Ablauf + claim_token, renew/release,
- abgelaufener oder freigegebener Claim wird automatisch wieder claimbar,
- ACL je Space wiederverwendet die Task-Rechte: CAP_CLAIM (can_claim_tasks) zum
  Claimen/Erneuern/Freigeben, CAP_READ zum Listen,
- Audit-Events fuer jede Aenderung. KEINE Secrets.

Genau EINE Zeile je (space_id, resource_key) (UNIQUE). "Aktiv" = released_at IS NULL UND
lease_until > now. Reine interne Service-Schicht - KEIN Netzwerk/MCP/Web hier.
"""
import secrets

from . import acl
from . import audit
from . import models as m
from . import spaces
from .errors import ClaimConflict, NotFound, StaleToken
from .util import iso_plus, now_iso, pid

DEFAULT_LEASE_SECONDS = 900
MAX_KEY_LEN = 512


def _space(conn, space):
    sp = spaces.get_space(conn, space)
    if not sp:
        raise NotFound("space not found: %s" % space)
    return sp


def _validate_key(resource_key):
    if not isinstance(resource_key, str) or not resource_key.strip():
        raise ClaimConflict("resource_key must be a non-empty string")
    rk = resource_key.strip()
    if len(rk) > MAX_KEY_LEN:
        raise ClaimConflict("resource_key too long (max %d chars)" % MAX_KEY_LEN)
    return rk


def claim_resource(conn, principal_id, space, resource_key,
                   lease_seconds=DEFAULT_LEASE_SECONDS, note=None):
    """Atomarer Claim. Erfolg nur, wenn die Ressource frei ist (noch nie geclaimt,
    freigegeben, oder Lease abgelaufen). Genau EIN paralleler Claimer gewinnt."""
    principal_id = pid(principal_id)
    sp = _space(conn, space)
    acl.require(conn, principal_id, sp["id"], m.CAP_CLAIM)
    resource_key = _validate_key(resource_key)
    now = now_iso()
    lease_until = iso_plus(lease_seconds)
    token = secrets.token_hex(16)
    # 1) Zeile anlegen, falls noch keine existiert. UNIQUE(space_id, resource_key) +
    #    SQLite-Write-Serialisierung => bei einem frischen Key gewinnt genau einer.
    cur = conn.execute(
        "INSERT OR IGNORE INTO resource_claims "
        "(space_id, resource_key, holder_id, claim_token, claimed_at, lease_until, note, "
        " released_at) VALUES (?,?,?,?,?,?,?,NULL)",
        (sp["id"], resource_key, str(principal_id), token, now, lease_until, note))
    if cur.rowcount != 1:
        # 2) Zeile existiert schon -> nur uebernehmen, wenn frei (freigegeben ODER abgelaufen).
        cur = conn.execute(
            "UPDATE resource_claims SET holder_id=?, claim_token=?, claimed_at=?, "
            "lease_until=?, note=?, released_at=NULL "
            "WHERE space_id=? AND resource_key=? "
            "  AND (released_at IS NOT NULL OR lease_until < ?)",
            (str(principal_id), token, now, lease_until, note, sp["id"], resource_key, now))
        if cur.rowcount != 1:
            conn.rollback()
            raise ClaimConflict(
                "resource '%s' is already claimed in space %s" % (resource_key, sp["key"]))
    audit.log(conn, principal_id, "resource_claimed", "resource", resource_key, sp["id"],
              {"lease_until": lease_until})
    conn.commit()
    return {"space": sp["key"], "resource_key": resource_key, "claim_token": token,
            "lease_until": lease_until}


def renew_resource(conn, principal_id, space, resource_key, claim_token,
                   lease_seconds=DEFAULT_LEASE_SECONDS):
    """Verlaengert die Lease. Nur der aktuelle Halter mit gueltigem (nicht abgelaufenem)
    claim_token kann erneuern; sonst StaleToken."""
    principal_id = pid(principal_id)
    sp = _space(conn, space)
    acl.require(conn, principal_id, sp["id"], m.CAP_CLAIM)
    resource_key = _validate_key(resource_key)
    now = now_iso()
    lease_until = iso_plus(lease_seconds)
    cur = conn.execute(
        "UPDATE resource_claims SET lease_until=? "
        "WHERE space_id=? AND resource_key=? AND holder_id=? AND claim_token=? "
        "  AND released_at IS NULL AND lease_until > ?",
        (lease_until, sp["id"], resource_key, str(principal_id), claim_token, now))
    if cur.rowcount != 1:
        conn.rollback()
        raise StaleToken("not the current holder of '%s' (or lease expired)" % resource_key)
    audit.log(conn, principal_id, "resource_renewed", "resource", resource_key, sp["id"],
              {"lease_until": lease_until})
    conn.commit()
    return {"space": sp["key"], "resource_key": resource_key, "claim_token": claim_token,
            "lease_until": lease_until}


def release_resource(conn, principal_id, space, resource_key, claim_token):
    """Gibt den eigenen Claim frei (setzt released_at). Nur mit passendem claim_token."""
    principal_id = pid(principal_id)
    sp = _space(conn, space)
    acl.require(conn, principal_id, sp["id"], m.CAP_CLAIM)
    resource_key = _validate_key(resource_key)
    now = now_iso()
    cur = conn.execute(
        "UPDATE resource_claims SET released_at=? "
        "WHERE space_id=? AND resource_key=? AND holder_id=? AND claim_token=? "
        "  AND released_at IS NULL",
        (now, sp["id"], resource_key, str(principal_id), claim_token))
    if cur.rowcount != 1:
        conn.rollback()
        raise StaleToken("not the current holder of '%s' (or already released)" % resource_key)
    audit.log(conn, principal_id, "resource_released", "resource", resource_key, sp["id"], {})
    conn.commit()
    return {"space": sp["key"], "resource_key": resource_key, "released": True}


def _holder_name(conn, holder_id):
    p = acl.get_principal(conn, holder_id)
    return p["name"] if p else None


def list_resource_claims(conn, principal_id, space=None, active_only=True, limit=200):
    """Listet Ressourcen-Claims, gefiltert auf Spaces mit Lese-Recht (ADMIN sieht alles).
    active_only=True -> nur aktive (nicht freigegeben, nicht abgelaufen)."""
    principal_id = pid(principal_id)
    limit = max(1, min(int(limit), 1000))
    now = now_iso()
    params = []
    sql = ("SELECT rc.*, s.key AS space_key FROM resource_claims rc "
           "JOIN spaces s ON s.id = rc.space_id")
    where = []
    if space is not None:
        sp = _space(conn, space)
        acl.require(conn, principal_id, sp["id"], m.CAP_READ)
        where.append("rc.space_id = ?")
        params.append(sp["id"])
    if active_only:
        where.append("rc.released_at IS NULL AND rc.lease_until > ?")
        params.append(now)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY rc.lease_until DESC LIMIT ?"
    params.append(limit)
    out = []
    for r in conn.execute(sql, params):
        row = dict(r)
        # ACL-Filter (falls kein konkreter Space angefragt wurde): nur lesbare Spaces.
        if space is None and not acl.check_permission(conn, principal_id, row["space_id"],
                                                      m.CAP_READ):
            continue
        active = row["released_at"] is None and row["lease_until"] > now
        out.append({"space": row["space_key"], "resource_key": row["resource_key"],
                    "holder": _holder_name(conn, row["holder_id"]),
                    "claimed_at": row["claimed_at"], "lease_until": row["lease_until"],
                    "released_at": row["released_at"], "note": row["note"],
                    "active": active})
    return out
