"""Service-Tokens fuer Agenten/Services.

Sicherheit:
- Klartext-Token NIE gespeichert; nur sha256(secret) als token_hash.
- Klartext nur EINMAL bei Erstellung/Rotation zurueckgegeben.
- Vergleich timing-safe (hmac.compare_digest).
- Token/Secret NIE ins Audit/Logs. token_id (oeffentlich) darf auditiert werden.
- Zufall kryptografisch sicher (secrets).
"""
import hashlib
import hmac
import secrets

from . import acl
from . import audit
from .errors import AuthFailed, BrainyError, NotFound
from .util import iso_plus, now_iso, pid

TOKEN_PREFIX = "bk"


def _hash(secret):
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def create_service_token(conn, principal_id, description="", ttl_seconds=None,
                         expires_at=None, actor=None):
    p = acl.get_principal(conn, pid(principal_id))
    if not p:
        raise NotFound("principal %s" % principal_id)
    if not p["active"]:
        raise BrainyError("principal inaktiv -> kein Token")
    token_id = "%s_%s" % (TOKEN_PREFIX, secrets.token_hex(6))
    secret = secrets.token_urlsafe(32)
    now = now_iso()
    exp = expires_at or (iso_plus(ttl_seconds) if ttl_seconds else None)
    conn.execute(
        "INSERT INTO service_tokens(token_id, principal_id, token_hash, description, "
        "created_at, expires_at, active) VALUES(?, ?, ?, ?, ?, ?, 1)",
        (token_id, p["id"], _hash(secret), description or "", now, exp),
    )
    # KEIN Secret/Hash ins Audit
    audit.log(conn, actor or p["id"], "token_created", "service_token", token_id,
              None, {"expires_at": exp})
    conn.commit()
    # Klartext NUR hier, EINMALIG:
    return {"token_id": token_id, "token": "%s.%s" % (token_id, secret),
            "expires_at": exp}


def _row(conn, token_id):
    r = conn.execute("SELECT * FROM service_tokens WHERE token_id=?",
                     (token_id,)).fetchone()
    return dict(r) if r else None


def touch_last_used(conn, token_id):
    conn.execute("UPDATE service_tokens SET last_used_at=? WHERE token_id=?",
                 (now_iso(), token_id))
    conn.commit()


def authenticate_service_token(conn, token):
    """Prueft ein Klartext-Token. Rueckgabe (principal_id, token_id) oder AuthFailed.
    Bei Misserfolg wird ein auth_failed-Audit OHNE Token/Secret geschrieben."""
    def fail(reason, token_id=None):
        audit.log(conn, token_id, "auth_failed", "service_token", token_id, None,
                  {"reason": reason}, commit=True)   # nur harmlose Metadaten
        raise AuthFailed(reason)

    if not token or "." not in str(token):
        fail("malformed")
    token_id, secret = str(token).split(".", 1)
    row = _row(conn, token_id)
    if not row:
        fail("unknown", token_id)
    if not row["active"] or row["revoked_at"]:
        fail("revoked", token_id)
    if row["expires_at"] and row["expires_at"] < now_iso():
        fail("expired", token_id)
    if not hmac.compare_digest(str(row["token_hash"]), _hash(secret)):
        fail("bad_secret", token_id)
    p = acl.get_principal(conn, row["principal_id"])
    if not p or not p["active"]:
        fail("principal_inactive", token_id)
    touch_last_used(conn, token_id)
    audit.log(conn, p["id"], "auth_success", "service_token", token_id, None,
              {"principal_id": p["id"]}, commit=True)
    return p["id"], token_id


def revoke_service_token(conn, token_id, actor=None):
    row = _row(conn, token_id)
    if not row:
        raise NotFound("token %s" % token_id)
    conn.execute("UPDATE service_tokens SET active=0, revoked_at=? WHERE token_id=?",
                 (now_iso(), token_id))
    audit.log(conn, actor or row["principal_id"], "token_revoked", "service_token",
              token_id, None, {})
    conn.commit()


def rotate_service_token(conn, token_id, description=None, actor=None):
    """Erzeugt einen NEUEN Token fuer denselben Principal und revoked den alten
    kontrolliert. Rueckgabe: neuer Klartext (einmalig)."""
    row = _row(conn, token_id)
    if not row:
        raise NotFound("token %s" % token_id)
    neu = create_service_token(conn, row["principal_id"],
                               description=description or row["description"],
                               expires_at=row["expires_at"], actor=actor)
    revoke_service_token(conn, token_id, actor=actor)
    audit.log(conn, actor or row["principal_id"], "token_rotated", "service_token",
              token_id, None, {"new_token_id": neu["token_id"]}, commit=True)
    return neu


def list_service_tokens(conn, principal_id):
    """Ohne token_hash/Secret."""
    rows = conn.execute(
        "SELECT token_id, principal_id, description, created_at, expires_at, "
        "revoked_at, last_used_at, active FROM service_tokens WHERE principal_id=? "
        "ORDER BY created_at DESC", (pid(principal_id),))
    return [dict(r) for r in rows]


def list_all_service_tokens(conn):
    """Alle Tokens (Admin-Uebersicht) OHNE token_hash/Secret."""
    rows = conn.execute(
        "SELECT token_id, principal_id, description, created_at, expires_at, "
        "revoked_at, last_used_at, active FROM service_tokens ORDER BY created_at DESC")
    return [dict(r) for r in rows]
