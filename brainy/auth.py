"""AuthContext + Token-Auth + externe Identitaet (SSO-Anschluss) + Bootstrap.

KEINE HTTP-/Header-Logik hier (Phase D). Kein Netzwerkdienst. KEIN Token/Secret
in AuthContext (nur der oeffentliche token_id).
"""
from dataclasses import dataclass, field
from typing import List, Optional

from . import acl
from . import audit
from . import models as m
from . import tokens
from .errors import AuthFailed, BrainyError, NotFound
from .util import now_iso, pid


@dataclass
class AuthContext:
    principal_id: int
    principal_type: str
    role: str
    active: bool
    allowed_spaces: List[str] = field(default_factory=list)  # [] , Keys, oder ["*"] (ADMIN)
    auth_method: str = "internal"
    token_id: Optional[str] = None                            # oeffentlich; KEIN Secret
    scopes: Optional[List[str]] = None                        # None = keine OAuth-Scope-Grenze

    def is_admin(self):
        return self.role == m.ADMIN


def _allowed_spaces(conn, principal):
    if principal["role"] == m.ADMIN:
        return ["*"]
    rows = conn.execute(
        "SELECT s.key FROM space_acl a JOIN spaces s ON s.id=a.space_id "
        "WHERE a.principal_id=? AND s.active=1 ORDER BY s.key", (principal["id"],))
    return [r["key"] for r in rows]


def context_for_principal(conn, principal_id, auth_method="internal", token_id=None):
    p = acl.get_principal(conn, pid(principal_id))
    if not p:
        raise NotFound("principal %s" % principal_id)
    return AuthContext(
        principal_id=p["id"], principal_type=p["principal_type"], role=p["role"],
        active=bool(p["active"]), allowed_spaces=_allowed_spaces(conn, p),
        auth_method=auth_method, token_id=token_id)


def authenticate_token(conn, token):
    """Klartext-Service-Token -> AuthContext (oder AuthFailed). Legacy-Pfad, unveraendert."""
    principal_id, token_id = tokens.authenticate_service_token(conn, token)
    return context_for_principal(conn, principal_id, auth_method="service_token",
                                 token_id=token_id)


def authenticate_bearer(conn, token):
    """Kombinierter Bearer-Pfad: Service-Token (Legacy) ODER OAuth-Access-Token.
    Service-Tokens enthalten '.'; OAuth-Access-Tokens beginnen mit 'brat_'."""
    if token and "." in token:
        return authenticate_token(conn, token)          # Service-Token (auditiert intern)
    from . import oauth
    res = oauth.authenticate_access_token(conn, token)
    if res:
        principal_id, scopes = res
        ctx = context_for_principal(conn, principal_id, auth_method="oauth")
        ctx.scopes = scopes
        audit.log(conn, principal_id, "auth_success", "oauth_token", None, None,
                  {"via": "oauth"}, commit=True)          # KEIN Tokenwert
        return ctx
    raise AuthFailed("no valid bearer token")


# ----- Externe Identitaet (SSO-Anschluss fuer Phase E) -----
def link_external_identity(conn, admin_id, provider, external_subject, principal_id):
    """Explizites Mapping externer Subject -> Principal. Nur ADMIN. Kein Auto-Anlegen."""
    if not acl.is_admin(conn, admin_id):
        raise BrainyError("only ADMIN may link external identities")
    conn.execute(
        "INSERT OR REPLACE INTO external_identities(provider, external_subject, "
        "principal_id, created_at) VALUES(?, ?, ?, ?)",
        (provider, external_subject, pid(principal_id), now_iso()))
    audit.log(conn, admin_id, "principal_updated", "principal", pid(principal_id), None,
              {"external_link": provider})
    conn.commit()


def resolve_external_identity(conn, provider, external_subject, email=None, name=None):
    """Nach externem SSO: Principal aufloesen. UNBEKANNT -> None (default deny),
    KEIN automatisches Anlegen, KEIN Auto-ADMIN. Mapping muss explizit existieren."""
    r = conn.execute(
        "SELECT principal_id FROM external_identities WHERE provider=? AND external_subject=?",
        (provider, external_subject)).fetchone()
    if not r:
        return None
    p = acl.get_principal(conn, r["principal_id"])
    if not p or not p["active"]:
        return None
    return context_for_principal(conn, p["id"], auth_method="sso:" + str(provider))


# ----- Bootstrap -----
def bootstrap_admin(conn, name="bootstrap-admin", with_token=False):
    """Legt EINEN ADMIN-Principal an — NUR wenn der Principal-Store leer ist.
    Kein Default-Passwort, kein fest eingebautes Token. Service-Token nur bei
    with_token=True (Klartext einmalig). Wird NICHT automatisch beim Import ausgefuehrt."""
    n = conn.execute("SELECT COUNT(*) AS c FROM principals").fetchone()["c"]
    if n > 0:
        raise BrainyError("principal store not empty -> bootstrap refused")
    p = acl.create_principal(conn, m.USER, name, m.ADMIN, actor="bootstrap")
    token = None
    if with_token:
        token = tokens.create_service_token(conn, p["id"], description="bootstrap",
                                            actor="bootstrap")["token"]
    return {"principal_id": p["id"], "name": name, "token": token}
