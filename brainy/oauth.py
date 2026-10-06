"""Eingebetteter OAuth-2.1-Authorization-Server (Phase O6A), MCP-kompatibel.

- Authorization Code + **PKCE (S256, Pflicht)**, public Clients (kein Client-Secret).
- **Dynamic Client Registration** (RFC 7591) -> Claude braucht nur die MCP-URL.
- Discovery: Protected-Resource-Metadata (RFC 9728) + AS-Metadata (RFC 8414).
- Tokens/Codes werden **nur als sha256-Hash** gespeichert; Klartext genau einmal.
- Sichere Randomness via `secrets`; PKCE-Vergleich timing-safe; **keine eigene Krypto**.
- KEINE Tokenwerte in Logs/Audit. Governance/ACL bleibt serverseitig massgeblich —
  Scopes schraenken zusaetzlich ein, umgehen die ACL aber nie.
"""
import base64
import hashlib
import hmac
import json
import secrets
from urllib.parse import urlparse

from . import acl, audit
from .errors import BrainyError
from .util import iso_plus, now_iso, pid

SCOPES = ["brainy:knowledge:read", "brainy:knowledge:write",
          "brainy:tasks:read", "brainy:tasks:write"]


class OAuthError(BrainyError):
    """OAuth-Fehler mit RFC-6749-Fehlercode."""
    def __init__(self, error, description="", status=400):
        super().__init__(description or error)
        self.error = error
        self.description = description
        self.status = status


# ---------------------------------------------------------------- Helpers
def _h(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def verify_pkce(verifier, challenge, method="S256"):
    if method != "S256" or not verifier or not challenge:
        return False
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    calc = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return hmac.compare_digest(calc, challenge)


def _valid_redirect(u):
    """Exakte, sichere Redirect-URIs: https mit Host, oder http://localhost (nur Tests)."""
    try:
        p = urlparse(u)
    except Exception:
        return False
    if p.scheme == "https" and p.netloc:
        return True
    if p.scheme == "http" and (p.hostname in ("localhost", "127.0.0.1")):
        return True
    return False


def _norm_scope(requested):
    """Nur bekannte Scopes durchlassen; leer -> alle Standard-Scopes."""
    if not requested:
        return " ".join(SCOPES)
    want = [s for s in str(requested).split() if s in SCOPES]
    return " ".join(want) if want else " ".join(SCOPES)


# ---------------------------------------------------------------- DCR
def register_client(conn, client_name, redirect_uris, scope=None, grant_types=None,
                    token_endpoint_auth_method="none", created_via="dcr"):
    if not redirect_uris or not isinstance(redirect_uris, list):
        raise OAuthError("invalid_redirect_uri", "redirect_uris (array) required")
    for u in redirect_uris:
        if not _valid_redirect(u):
            raise OAuthError("invalid_redirect_uri", "insecure/invalid redirect_uri")
    cid = "brainy-client-" + secrets.token_hex(10)
    conn.execute(
        "INSERT INTO oauth_clients(client_id, client_name, redirect_uris, grant_types, "
        "scope, token_endpoint_auth_method, created_at, created_via) VALUES(?,?,?,?,?,?,?,?)",
        (cid, (client_name or "")[:120], json.dumps(redirect_uris),
         " ".join(grant_types or ["authorization_code", "refresh_token"]),
         _norm_scope(scope), token_endpoint_auth_method, now_iso(), created_via))
    audit.log(conn, "oauth", "oauth_client_registered", "oauth_client", cid, None,
              {"name": (client_name or "")[:60], "redirect_uris": redirect_uris},
              commit=True)   # KEINE Secrets
    return get_client(conn, cid)


def get_client(conn, client_id):
    r = conn.execute("SELECT * FROM oauth_clients WHERE client_id=?", (client_id,)).fetchone()
    if not r:
        return None
    d = dict(r)
    d["redirect_uris"] = json.loads(d["redirect_uris"])
    return d


def client_public(client):
    return {"client_id": client["client_id"], "client_name": client["client_name"],
            "redirect_uris": client["redirect_uris"],
            "grant_types": client["grant_types"].split(),
            "token_endpoint_auth_method": client["token_endpoint_auth_method"],
            "scope": client["scope"]}


# ---------------------------------------------------------------- Authorization Code
def create_auth_code(conn, client_id, principal_id, redirect_uri, scope, code_challenge,
                     code_challenge_method="S256", ttl=None):
    from . import config
    code = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO oauth_auth_codes(code_hash, client_id, principal_id, redirect_uri, "
        "scope, code_challenge, code_challenge_method, expires_at, created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (_h(code), client_id, pid(principal_id), redirect_uri, _norm_scope(scope),
         code_challenge, code_challenge_method,
         iso_plus(ttl or config.OAUTH_CODE_TTL), now_iso()))
    audit.log(conn, pid(principal_id), "oauth_code_issued", "oauth_client", client_id, None,
              {"scope": _norm_scope(scope)})
    conn.commit()
    return code                       # Klartext genau einmal


def _issue_token(conn, token_type, client_id, principal_id, scope, ttl, auth_code_hash=None):
    prefix = "brat_" if token_type == "access" else "brrt_"
    token = prefix + secrets.token_urlsafe(32)
    exp = iso_plus(ttl) if ttl else None
    conn.execute(
        "INSERT INTO oauth_tokens(token_hash, token_type, client_id, principal_id, scope, "
        "expires_at, auth_code_hash, created_at) VALUES(?,?,?,?,?,?,?,?)",
        (_h(token), token_type, client_id, pid(principal_id), scope, exp,
         auth_code_hash, now_iso()))
    return token


def exchange_code(conn, code, client_id, redirect_uri, code_verifier):
    from . import config
    row = conn.execute("SELECT * FROM oauth_auth_codes WHERE code_hash=?", (_h(code or ""),)).fetchone()
    if not row:
        raise OAuthError("invalid_grant", "unknown code")
    r = dict(row)
    if r["used_at"]:
        # Code-Reuse (OAuth 2.1): nur die AUS DIESEM Code abgeleiteten Tokens widerrufen.
        conn.execute("UPDATE oauth_tokens SET revoked_at=? WHERE auth_code_hash=? "
                     "AND revoked_at IS NULL", (now_iso(), _h(code)))
        conn.commit()
        raise OAuthError("invalid_grant", "code already used")
    if r["expires_at"] < now_iso():
        raise OAuthError("invalid_grant", "code expired")
    if r["client_id"] != client_id:
        raise OAuthError("invalid_grant", "client_id mismatch")
    if r["redirect_uri"] != redirect_uri:
        raise OAuthError("invalid_grant", "redirect_uri mismatch")
    if not verify_pkce(code_verifier, r["code_challenge"], r["code_challenge_method"]):
        raise OAuthError("invalid_grant", "PKCE verification failed")
    conn.execute("UPDATE oauth_auth_codes SET used_at=? WHERE code_hash=?", (now_iso(), _h(code)))
    ch = _h(code)
    at = _issue_token(conn, "access", client_id, r["principal_id"], r["scope"],
                      config.OAUTH_ACCESS_TTL, auth_code_hash=ch)
    rt = _issue_token(conn, "refresh", client_id, r["principal_id"], r["scope"],
                      config.OAUTH_REFRESH_TTL, auth_code_hash=ch)
    audit.log(conn, r["principal_id"], "oauth_token_issued", "oauth_client", client_id, None,
              {"grant": "authorization_code", "scope": r["scope"]})
    conn.commit()
    return {"access_token": at, "token_type": "Bearer", "expires_in": config.OAUTH_ACCESS_TTL,
            "refresh_token": rt, "scope": r["scope"]}


def refresh_token(conn, refresh_tok, client_id):
    from . import config
    r = _lookup(conn, refresh_tok, "refresh")
    if not r:
        raise OAuthError("invalid_grant", "refresh token invalid/expired/revoked")
    if r["client_id"] != client_id:
        raise OAuthError("invalid_grant", "client_id mismatch")
    at = _issue_token(conn, "access", client_id, r["principal_id"], r["scope"], config.OAUTH_ACCESS_TTL)
    audit.log(conn, r["principal_id"], "oauth_token_issued", "oauth_client", client_id, None,
              {"grant": "refresh_token", "scope": r["scope"]})
    conn.commit()
    return {"access_token": at, "token_type": "Bearer", "expires_in": config.OAUTH_ACCESS_TTL,
            "scope": r["scope"]}


def _lookup(conn, token, token_type):
    if not token:
        return None
    r = conn.execute("SELECT * FROM oauth_tokens WHERE token_hash=? AND token_type=?",
                     (_h(token), token_type)).fetchone()
    if not r:
        return None
    r = dict(r)
    if r["revoked_at"]:
        return None
    if r["expires_at"] and r["expires_at"] < now_iso():
        return None
    p = acl.get_principal(conn, r["principal_id"])
    if not p or not p["active"]:
        return None
    return r


def authenticate_access_token(conn, token):
    """Access-Token -> (principal_id, [scopes]) oder None. KEIN Audit hier (Aufrufer)."""
    if not token or not token.startswith("brat_"):
        return None
    r = _lookup(conn, token, "access")
    if not r:
        return None
    return r["principal_id"], (r["scope"] or "").split()


def revoke(conn, token, actor="oauth"):
    """RFC 7009: Token widerrufen (access oder refresh). Idempotent, immer 200."""
    if not token:
        return
    r = conn.execute("SELECT token_hash, principal_id, client_id, token_type FROM oauth_tokens "
                     "WHERE token_hash=?", (_h(token),)).fetchone()
    if r:
        conn.execute("UPDATE oauth_tokens SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL",
                     (now_iso(), r["token_hash"]))
        audit.log(conn, actor, "oauth_token_revoked", "oauth_client", r["client_id"], None,
                  {"token_type": r["token_type"]})
        conn.commit()


def revoke_all_for_principal(conn, principal_id, actor="admin"):
    """Alle OAuth-Tokens eines Principals widerrufen (Client sauber sperren)."""
    conn.execute("UPDATE oauth_tokens SET revoked_at=? WHERE principal_id=? AND revoked_at IS NULL",
                 (now_iso(), pid(principal_id)))
    audit.log(conn, actor, "oauth_token_revoked", "principal", pid(principal_id), None,
              {"scope": "all"}, commit=True)


# ---------------------------------------------------------------- Discovery-Metadaten
def protected_resource_metadata(base_url):
    return {"resource": base_url + "/mcp", "authorization_servers": [base_url],
            "scopes_supported": SCOPES, "bearer_methods_supported": ["header"]}


def authorization_server_metadata(base_url):
    return {
        "issuer": base_url,
        "authorization_endpoint": base_url + "/oauth/authorize",
        "token_endpoint": base_url + "/oauth/token",
        "registration_endpoint": base_url + "/oauth/register",
        "revocation_endpoint": base_url + "/oauth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": SCOPES,
    }
