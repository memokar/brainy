"""Brainy Web/Admin-Oberflaeche (Phase E).

Serverseitig gerenderte HTML-Templates + minimal JS (kein SPA, keine Build-Pipeline).
Alle Aktionen laufen ausschliesslich ueber die bestehende Service-Schicht
(tasks/knowledge/acl/audit) — KEIN direktes SQL aus Routen, KEINE Shell, KEINE
generische FS-API. Auth: signierte Session-Cookies (HMAC), Login per bestehendem
Brainy-Service-Token (KEIN Default-Passwort). Writes: POST + CSRF + ACL + Audit.

Vorbereitung tool_portal-SSO: `auth.resolve_external_identity` (default deny, kein
Auto-ADMIN) ist der Andockpunkt; der Login unten nutzt vorerst lokale Token-Session.
"""
import hashlib
import hmac
import html
import time
import urllib.parse

from . import acl, agents, audit, auth, capabilities as cap, config, dispatcher, knowledge
from . import models as m, oauth, settings, spaces, tasks
from . import tokens as toks
from .errors import (AuthFailed, BrainyError, Conflict, InvalidState, NotFound,
                     PermissionDenied, SecretDetected)
from .paths import PathNotAllowed
from .util import loads

SESSION_TTL = 8 * 3600          # 8 h
COOKIE = "brainy_admin"
_ACTIVE_CLAIM = {m.CLAIMED, m.IN_PROGRESS}

# Security-Header auf JEDER Web-Antwort (nginx setzt zusaetzlich HSTS/TLS).
# Standard: form-action 'self'. NUR die OAuth-Consent-Seite ergaenzt gezielt die EXAKTE
# Origin ihrer validierten redirect_uri (z. B. https://claude.ai), damit der OAuth-303-
# Redirect nicht von der CSP blockiert wird. Kein Wildcard, keine globale Lockerung.
def _csp(form_action_extra=""):
    fa = "'self'" + ((" " + form_action_extra) if form_action_extra else "")
    return ("default-src 'none'; style-src 'unsafe-inline'; form-action %s; "
            "base-uri 'none'; frame-ancestors 'none'" % fa)


def _sec_headers(form_action_extra=""):
    return [("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("X-Frame-Options", "DENY"),
            ("Content-Security-Policy", _csp(form_action_extra)),
            ("Cache-Control", "no-store")]


def _esc(x):
    return html.escape("" if x is None else str(x), quote=True)


# ------------------------------------------------------------- Session / CSRF
def _sign(secret, data):
    return hmac.new(secret, data.encode("utf-8"), hashlib.sha256).hexdigest()


def make_session(secret, principal_id):
    exp = int(time.time()) + SESSION_TTL
    base = "%s|%d" % (principal_id, exp)
    return "%s|%s" % (base, _sign(secret, base))


def parse_session(secret, value):
    """Signiertes Cookie -> principal_id (int) oder None. Timing-safe, mit Ablauf."""
    if not value or value.count("|") != 2:
        return None
    pid_s, exp_s, sig = value.split("|")
    base = "%s|%s" % (pid_s, exp_s)
    if not hmac.compare_digest(sig, _sign(secret, base)):
        return None
    try:
        if int(exp_s) < int(time.time()):
            return None
        return int(pid_s)
    except ValueError:
        return None


def csrf_token(secret, session_value):
    return _sign(secret, "csrf|" + (session_value or ""))[:32]


def _cookie_value(cookie_header):
    if not cookie_header:
        return None
    for part in str(cookie_header).split(";"):
        k, _, v = part.strip().partition("=")
        if k == COOKIE:
            return v
    return None


# ------------------------------------------------------------- HTML-Bausteine
_STYLE = """
:root{--fg:#1c2530;--muted:#5b6b7b;--bg:#f6f8fa;--card:#fff;--line:#dfe6ee;
--accent:#2f6feb;--bad:#c0392b;--ok:#1e8e57;--warn:#b9770e}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 -apple-system,Segoe UI,Roboto,
Helvetica,Arial,sans-serif;color:var(--fg);background:var(--bg)}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
header{background:#1c2530;color:#fff;padding:10px 18px;display:flex;gap:16px;
align-items:center;flex-wrap:wrap}header .b{font-weight:700;letter-spacing:.5px}
header a{color:#cfe0ff}header .sp{margin-left:auto;color:#9fb3c8;font-size:13px}
main{max-width:1080px;margin:0 auto;padding:18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;
padding:14px 16px;margin:0 0 16px}
h1{font-size:20px;margin:.1em 0 .6em}h2{font-size:16px;margin:.2em 0 .5em}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);
vertical-align:top}th{color:var(--muted);font-weight:600;font-size:12px;
text-transform:uppercase;letter-spacing:.4px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}
.kpi b{display:block;font-size:24px}.kpi span{color:var(--muted);font-size:12px}
.badge{display:inline-block;padding:1px 8px;border-radius:20px;font-size:12px;
border:1px solid var(--line);color:var(--muted)}
.badge.ok{color:var(--ok);border-color:#bfe6d0}.badge.bad{color:var(--bad);
border-color:#f0c6bf}.badge.warn{color:var(--warn);border-color:#f0dcae}
input,select,textarea{font:inherit;padding:7px 9px;border:1px solid var(--line);
border-radius:6px;background:#fff;max-width:100%}textarea{width:100%;min-height:340px;
font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
button,.btn{font:inherit;padding:7px 13px;border:1px solid var(--line);border-radius:6px;
background:#fff;cursor:pointer}button.primary{background:var(--accent);color:#fff;
border-color:var(--accent)}button.danger{color:var(--bad);border-color:#f0c6bf}
form.inline{display:inline}pre{background:#0f1620;color:#e6edf3;padding:12px;
border-radius:8px;overflow:auto;font-size:12.5px;line-height:1.45}
.flash{padding:10px 12px;border-radius:6px;margin:0 0 14px;border:1px solid}
.flash.err{background:#fdECEA;border-color:#f0c6bf;color:#9a2b1e}
.flash.ok{background:#e9f7ef;border-color:#bfe6d0;color:#16663f}
.muted{color:var(--muted)}.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
.filters{display:flex;gap:8px;flex-wrap:wrap;align-items:end;margin-bottom:12px}
label.f{display:flex;flex-direction:column;font-size:12px;color:var(--muted);gap:3px}
.diff-add{color:#2ec16a}.diff-del{color:#ff6b6b}
"""

_NAV = [("/admin/", "Dashboard"), ("/admin/tasks", "Tasks"),
        ("/admin/agents", "Agents"), ("/admin/jobs", "Jobs"),
        ("/admin/knowledge", "Knowledge"), ("/admin/spaces", "Spaces"),
        ("/admin/principals", "Principals"), ("/admin/tokens", "Tokens"),
        ("/admin/audit", "Audit")]


def _page(title, body, ctx=None, flash=None):
    nav = " ".join('<a href="%s">%s</a>' % (h, l) for h, l in _NAV)
    who = ""
    if ctx is not None:
        who = '<span class="sp">%s &middot; %s &middot; <form class="inline" ' \
              'method="post" action="/admin/logout"><input type="hidden" name="csrf" ' \
              'value="%s"><button class="btn" style="padding:2px 8px">Logout</button>' \
              '</form></span>' % (_esc(getattr(ctx, "_name", "?")), _esc(ctx.role),
                                  _esc(getattr(ctx, "_csrf", "")))
    fl = ('<div class="flash %s">%s</div>' % (flash[0], _esc(flash[1]))) if flash else ""
    return ("<!doctype html><html lang=en><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>%s &middot; Brainy Admin</title><style>%s</style></head><body>"
            "<header><span class=b>BRAINY</span>%s%s</header><main>%s%s</main>"
            "</body></html>") % (_esc(title), _STYLE, nav, who, fl, body)


# ------------------------------------------------------------- Response-Helfer
def _html(status, body, extra=None, form_action_extra=""):
    hdrs = _sec_headers(form_action_extra)
    if extra:
        hdrs += extra
    return status, "text/html; charset=utf-8", hdrs, body.encode("utf-8")


def _redirect(location, extra=None):
    hdrs = _sec_headers() + [("Location", location)]
    if extra:
        hdrs += extra
    return 303, "text/html; charset=utf-8", hdrs, b""


def _form(body_bytes):
    q = urllib.parse.parse_qs((body_bytes or b"").decode("utf-8", "replace"),
                              keep_blank_values=True)
    return {k: v[0] for k, v in q.items()}


def _q(query):
    q = urllib.parse.parse_qs(query or "", keep_blank_values=True)
    return {k: v[0] for k, v in q.items()}


def _safe_next(nxt):
    """Nur lokale, erwartete Ziele erlauben (Open-Redirect-Schutz)."""
    if not nxt or nxt.startswith("//"):
        return ""
    if nxt.startswith("/admin") or nxt.startswith("/oauth/authorize"):
        return nxt
    return ""


def _err_redirect(redirect_uri, error, state):
    sep = "&" if "?" in redirect_uri else "?"
    return "%s%serror=%s&state=%s" % (redirect_uri, sep, urllib.parse.quote(error),
                                      urllib.parse.quote(state or ""))


class BrainyWeb:
    def __init__(self, service, session_secret):
        self.service = service
        if isinstance(session_secret, str):
            session_secret = session_secret.encode("utf-8")
        self.secret = session_secret

    # ---- Auth-Gate -------------------------------------------------------
    def _ctx(self, conn, cookie_header):
        pid = parse_session(self.secret, _cookie_value(cookie_header))
        if pid is None:
            return None
        p = acl.get_principal(conn, pid)
        if not p or not p["active"]:
            return None
        ctx = auth.context_for_principal(conn, pid, auth_method="web_session")
        ctx._name = p["name"]
        ctx._csrf = csrf_token(self.secret, _cookie_value(cookie_header))
        return ctx

    def _check_csrf(self, ctx, form):
        return hmac.compare_digest(form.get("csrf", ""), getattr(ctx, "_csrf", "x"))

    @staticmethod
    def _oauth_self_ok(conn, ctx):
        """Eingeschraenkter Mensch (USER, nicht ADMIN) mit metadata.oauth_self=true:
        darf OAuth NUR fuer sich selbst freigeben und sonst KEINE Web-Admin-Seite sehen."""
        if ctx is None or ctx.role == m.ADMIN:
            return False
        p = acl.get_principal(conn, ctx.principal_id)
        if not p or not p["active"] or p["principal_type"] != m.USER:
            return False
        meta = loads(p["metadata"], {}) or {}
        return isinstance(meta, dict) and meta.get("oauth_self") is True

    # ---- Dispatch --------------------------------------------------------
    def handle(self, method, path, query, cookie_header, body_bytes):
        try:
            return self._route(method, path, query, cookie_header, body_bytes)
        except PermissionDenied as e:
            return _html(403, _page("Forbidden", '<div class="card"><h1>403 &mdash; '
                        'access denied</h1><p class=muted>%s</p><p><a href="/admin/">'
                        'Back</a></p></div>' % _esc(str(e)[:200])))
        except (NotFound,) as e:
            return _html(404, _page("Not found", '<div class="card"><h1>404</h1>'
                        '<p class=muted>%s</p></div>' % _esc(str(e)[:200])))
        except (Conflict, SecretDetected, InvalidState, PathNotAllowed, BrainyError) as e:
            return _html(400, _page("Error", '<div class="card"><h1>Rejected</h1>'
                        '<p class=muted>%s</p><p><a href="/admin/">Back</a></p>'
                        '</div>' % _esc(str(e)[:300])))

    def _route(self, method, path, query, cookie_header, body):
        if path in ("/", "/admin"):
            return _redirect("/admin/")
        # --- Login / Logout (Login unauth) ---
        if path == "/admin/login":
            conn = self.service._conn()
            try:
                nxt = _safe_next(_q(query).get("next"))
                if method == "GET":
                    if self._ctx(conn, cookie_header):
                        return _redirect(nxt or "/admin/")
                    return _html(200, self._login_page(next_url=nxt))
                return self._do_login(conn, _form(body))
            finally:
                conn.close()
        if path == "/admin/logout":
            expire = [("Set-Cookie", "%s=; Path=/; HttpOnly; Secure; SameSite=Lax; "
                       "Max-Age=0" % COOKIE)]
            return _redirect("/admin/login", extra=expire)

        # --- OAuth-2.1 Authorization (Owner-Consent; nur ADMIN) ---
        if path == "/oauth/authorize":
            conn = self.service._conn()
            try:
                ctx = self._ctx(conn, cookie_header)
                if ctx is None:
                    nxt = "/oauth/authorize?" + query
                    return _redirect("/admin/login?next=" + urllib.parse.quote(nxt))
                if ctx.role == m.ADMIN:
                    target = config.OAUTH_PRINCIPAL
                elif self._oauth_self_ok(conn, ctx):
                    target = ctx._name   # Selbstfreigabe: Token laeuft unter dem eigenen Principal
                else:
                    return _html(403, _page("Forbidden", '<div class="card"><h1>403</h1>'
                                '<p class=muted>Only the Brainy owner (ADMIN) may authorize '
                                'OAuth clients.</p></div>', ctx))
                if method == "POST":
                    form = _form(body)
                    if not self._check_csrf(ctx, form):
                        return _html(403, _page("CSRF", '<div class="card">403 CSRF</div>', ctx))
                    return self._oauth_decide(conn, ctx, form, target)
                return self._oauth_consent(conn, ctx, _q(query), target)
            finally:
                conn.close()

        # --- ab hier: Session erforderlich ---
        conn = self.service._conn()
        try:
            ctx = self._ctx(conn, cookie_header)
            if ctx is None:
                return _redirect("/admin/login")
            if self._oauth_self_ok(conn, ctx):
                ok = method == "GET" and path == "/admin/"
                return _html(200 if ok else 403, (
                    "<!doctype html><html lang=en><head><meta charset=utf-8>"
                    "<meta name=viewport content='width=device-width,initial-scale=1'>"
                    "<title>Brainy</title><style>%s</style></head><body><main>"
                    '<div style="max-width:520px;margin:8vh auto"><div class="card">'
                    "<h1>Signed in as %s</h1><p>The Brainy web interface is locked for "
                    "this account. Connect Brainy in Claude now (connector) "
                    "&ndash; your approved area is available to you there.</p>"
                    '<p><a href="/admin/logout">Sign out</a></p></div></div>'
                    "</main></body></html>") % (_STYLE, _esc(ctx._name)))
            q = _q(query)
            # Writes: POST + CSRF
            if method == "POST":
                form = _form(body)
                if not self._check_csrf(ctx, form):
                    return _html(403, _page("CSRF", '<div class="card"><h1>403 CSRF</h1>'
                                '<p class=muted>Invalid or missing CSRF token.</p>'
                                '</div>', ctx))
                return self._post(conn, ctx, path, form)
            return self._get(conn, ctx, path, q)
        finally:
            conn.close()

    # ---- Login -----------------------------------------------------------
    def _login_page(self, err=None, next_url=""):
        fl = ('<div class="flash err">%s</div>' % _esc(err)) if err else ""
        nxt = ('<input type="hidden" name="next" value="%s">' % _esc(next_url)) if next_url else ""
        hint = ('<p class=muted>After signing in you will be returned to the OAuth authorization.</p>'
                if next_url.startswith("/oauth/authorize") else "")
        body = ('<div style="max-width:420px;margin:8vh auto"><div class="card">'
                '<h1>Brainy Admin</h1>' + fl + hint + '<p class=muted>Sign in with your '
                'Brainy service token. Only a signed session cookie is set; '
                'the token leaves the browser only once, at sign-in.</p>'
                '<form method="post" action="/admin/login">' + nxt +
                '<label class="f">Service token<input name="token" type="password" '
                'autocomplete="off" style="width:100%" autofocus></label>'
                '<p><button class="primary" type="submit">Sign in</button></p>'
                '</form></div><p class=muted style="text-align:center;font-size:12px">'
                'Unknown/expired tokens are rejected (default deny). '
                'No auto-ADMIN.</p></div>')
        return ("<!doctype html><html lang=en><head><meta charset=utf-8>"
                "<meta name=viewport content='width=device-width,initial-scale=1'>"
                "<title>Login &middot; Brainy Admin</title><style>%s</style></head>"
                "<body><main>%s</main></body></html>") % (_STYLE, body)

    def _do_login(self, conn, form):
        token = (form.get("token") or "").strip()
        nxt = _safe_next(form.get("next"))
        try:
            actx = auth.authenticate_token(conn, token)
        except AuthFailed:
            return _html(401, self._login_page("Invalid or expired token.", next_url=nxt))
        cookie = make_session(self.secret, actx.principal_id)
        setc = [("Set-Cookie", "%s=%s; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=%d"
                 % (COOKIE, cookie, SESSION_TTL))]
        audit.log(conn, actx.principal_id, "web_login", "web", "admin", None,
                  {"method": "service_token"}, commit=True)
        return _redirect(nxt or "/admin/", extra=setc)

    # ---- OAuth-2.1 Owner-Consent -----------------------------------------
    def _oauth_consent(self, conn, ctx, q, target=None):
        target = target or config.OAUTH_PRINCIPAL
        cl, redirect_uri, err = self._oauth_validate(conn, q)
        if err is not None:
            return err
        rt = q.get("response_type")
        state = q.get("state", "")
        cc = q.get("code_challenge")
        ccm = q.get("code_challenge_method", "S256")
        if rt != "code":
            return _redirect(_err_redirect(redirect_uri, "unsupported_response_type", state))
        if not cc or ccm != "S256":
            return _redirect(_err_redirect(redirect_uri, "invalid_request", state))
        scopes = oauth._norm_scope(q.get("scope")).split()
        acct = acl.get_principal_by_name(conn, target)
        if not acct or not acct["active"]:
            return _html(500, _page("OAuth", '<div class="card">OAuth principal missing.</div>', ctx))
        hidden = "".join('<input type="hidden" name="%s" value="%s">' % (k, _esc(q.get(k, "")))
                         for k in ("client_id", "redirect_uri", "response_type", "scope",
                                   "state", "code_challenge", "code_challenge_method"))
        scope_html = "".join("<li><span class=mono>%s</span></li>" % _esc(s) for s in scopes)
        body = ('<div style="max-width:520px;margin:6vh auto"><div class="card">'
                '<h1>Connect Brainy</h1>'
                '<p>Client <b>%s</b> wants to access your Brainy.</p>'
                '<table><tr><th>Client</th><td>%s</td></tr>'
                '<tr><th>Brainy-Principal</th><td class=mono>%s</td></tr>'
                '<tr><th>Redirect</th><td class=mono>%s</td></tr></table>'
                '<p class=muted style="margin-top:10px">Requested scopes:</p><ul>%s</ul>'
                '<p class=muted style="font-size:12px">Governance/ACL remain authoritative '
                'on the server; scopes can only restrict, never extend.</p>'
                '<form method="post" action="/oauth/authorize" style="display:flex;gap:8px">'
                '<input type="hidden" name="csrf" value="%s">%s'
                '<button class="primary" name="decision" value="approve">Allow</button>'
                '<button class="danger" name="decision" value="deny">Deny</button>'
                '</form></div></div>'
                % (_esc(cl["client_name"] or cl["client_id"]), _esc(cl["client_name"] or "—"),
                   _esc(target), _esc(redirect_uri), scope_html,
                   _esc(ctx._csrf), hidden))
        # CSP: exakte Origin der (bereits validierten) redirect_uri fuer den OAuth-303 zulassen.
        ru = urllib.parse.urlparse(redirect_uri)
        fa_origin = "%s://%s" % (ru.scheme, ru.netloc)
        return _html(200, ("<!doctype html><html lang=en><head><meta charset=utf-8>"
                     "<meta name=viewport content='width=device-width,initial-scale=1'>"
                     "<title>Brainy OAuth</title><style>%s</style></head><body><main>%s"
                     "</main></body></html>") % (_STYLE, body), form_action_extra=fa_origin)

    def _oauth_decide(self, conn, ctx, form, target=None):
        target = target or config.OAUTH_PRINCIPAL
        cl, redirect_uri, err = self._oauth_validate(conn, form)
        if err is not None:
            return err
        state = form.get("state", "")
        if form.get("decision") != "approve":
            audit.log(conn, ctx.principal_id, "oauth_consent_denied", "oauth_client",
                      cl["client_id"], None, {}, commit=True)
            return _redirect(_err_redirect(redirect_uri, "access_denied", state))
        acct = acl.get_principal_by_name(conn, target)
        if not acct or not acct["active"]:
            return _html(500, _page("OAuth", '<div class="card">OAuth principal missing.</div>', ctx))
        code = oauth.create_auth_code(conn, cl["client_id"], acct["id"], redirect_uri,
                                      form.get("scope"), form.get("code_challenge"),
                                      form.get("code_challenge_method", "S256"))
        audit.log(conn, ctx.principal_id, "oauth_consent_granted", "oauth_client",
                  cl["client_id"], None, {"by": ctx._name, "principal": target},
                  commit=True)
        sep = "&" if "?" in redirect_uri else "?"
        return _redirect("%s%scode=%s&state=%s" % (redirect_uri, sep,
                         urllib.parse.quote(code), urllib.parse.quote(state)))

    def _oauth_validate(self, conn, params):
        """Prüft client_id + exakte redirect_uri. Rückgabe (client, redirect_uri, err_response|None).
        Bei unbekanntem Client/ungültiger Redirect: KEIN Redirect (Open-Redirect-Schutz)."""
        cid = params.get("client_id")
        redirect_uri = params.get("redirect_uri")
        cl = oauth.get_client(conn, cid) if cid else None
        if not cl:
            return None, None, _html(400, _page("OAuth", '<div class="card"><h1>Invalid '
                                    'client</h1><p class=muted>Unknown client_id.</p></div>'))
        if not redirect_uri or redirect_uri not in cl["redirect_uris"]:
            return None, None, _html(400, _page("OAuth", '<div class="card"><h1>Invalid '
                                    'redirect_uri</h1><p class=muted>Not registered for this '
                                    'client.</p></div>'))
        return cl, redirect_uri, None

    # ---- GET-Routen ------------------------------------------------------
    def _get(self, conn, ctx, path, q):
        root = self.service.knowledge_root
        if path == "/admin/":
            return _html(200, self._dashboard(conn, ctx))
        if path == "/admin/tasks":
            return _html(200, self._tasks(conn, ctx, q))
        if path == "/admin/tasks/view":
            return _html(200, self._task_detail(conn, ctx, q.get("id")))
        if path == "/admin/knowledge":
            return _html(200, self._knowledge(conn, ctx, root))
        if path == "/admin/knowledge/view":
            return _html(200, self._doc_view(conn, ctx, q.get("path"), root))
        if path == "/admin/knowledge/search":
            return _html(200, self._doc_search(conn, ctx, q.get("q", ""), root))
        if path == "/admin/knowledge/history":
            return _html(200, self._doc_history(conn, ctx, q.get("path"), root))
        if path == "/admin/knowledge/diff":
            return _html(200, self._doc_diff(conn, ctx, q.get("path"),
                                             q.get("from"), q.get("to"), root))
        if path == "/admin/knowledge/edit":
            return _html(200, self._doc_edit(conn, ctx, q.get("path"), root))
        if path == "/admin/agents":
            return _html(200, self._agents(conn, ctx))
        if path == "/admin/jobs":
            return _html(200, self._jobs(conn, ctx, q))
        if path == "/admin/spaces":
            return _html(200, self._spaces(conn, ctx))
        if path == "/admin/principals":
            return _html(200, self._principals(conn, ctx))
        if path == "/admin/tokens":
            return _html(200, self._tokens(conn, ctx))
        if path == "/admin/audit":
            return _html(200, self._audit(conn, ctx, q))
        return _html(404, _page("404", '<div class="card">Unknown route.</div>', ctx))

    # ---- POST-Routen -----------------------------------------------------
    def _post(self, conn, ctx, path, form):
        if path == "/admin/tasks/create":
            dep = (form.get("dependency") or "").strip()
            t = tasks.create_task(
                conn, ctx, _need(form, "space"), _need(form, "title"),
                type=form.get("type") or "chore", priority=form.get("priority") or "P3",
                description=form.get("description") or "",
                status=(m.READY if form.get("status") == "READY" else m.OPEN),
                execution_mode=form.get("execution_mode") or None,
                risk_level=form.get("risk_level") or None,
                action_class=form.get("action_class") or None,
                preferred_agent=form.get("preferred_agent") or None,
                dependencies=[dep] if dep else None)
            return _redirect("/admin/tasks/view?id=" + t["task_id"])
        if path == "/admin/tasks/action":
            return self._task_action(conn, ctx, form)
        if path == "/admin/tasks/govern":
            return self._task_govern(conn, ctx, form)
        if path == "/admin/dispatcher/toggle":
            if (form.get("action") or "") == "resume":
                dispatcher.resume_dispatcher(conn, ctx)
            else:
                dispatcher.pause_dispatcher(conn, ctx)
            return _redirect("/admin/")
        if path == "/admin/agents/toggle":
            agents.set_enabled(conn, ctx, _need(form, "agent_name"),
                               (form.get("action") or "") == "enable")
            return _redirect("/admin/agents")
        if path == "/admin/knowledge/save":
            res = knowledge.write_document(
                conn, ctx, _need(form, "path"), form.get("content", ""),
                form.get("expected_git_commit") or None, _need(form, "commit_message"),
                root=self.service.knowledge_root)
            return _redirect("/admin/knowledge/view?path=" +
                             urllib.parse.quote(res["path"]))
        return _html(404, _page("404", '<div class="card">Unknown action.</div>', ctx))

    def _task_action(self, conn, ctx, form):
        tid = _need(form, "id")
        action = form.get("action")
        t = tasks.get_task(conn, tid)
        if not t:
            raise NotFound(tid)
        # Aktiven Agent-Claim NIE ueber die Admin-UI ueberschreiben.
        if t["status"] in _ACTIVE_CLAIM:
            return _html(409, _page("Active claim", '<div class="card"><h1>409 &mdash; '
                        'active claim</h1><p class=muted>Task <span class=mono>%s</span> '
                        'is %s (being worked on by an agent). An active claim is never '
                        'overridden via the admin UI.</p><p><a href="/admin/'
                        'tasks/view?id=%s">Back</a></p></div>'
                        % (_esc(tid), _esc(t["status"]), _esc(tid)), ctx))
        target = {"ready": m.READY, "unblock": m.READY, "block": m.BLOCKED,
                  "cancel": m.CANCELLED}.get(action)
        if not target:
            raise BrainyError("unknown action: %s" % action)
        tasks.set_status(conn, ctx, tid, target)
        return _redirect("/admin/tasks/view?id=" + tid)

    # ---- Views -----------------------------------------------------------
    def _dashboard(self, conn, ctx):
        h = self.service.health()
        sp_all = spaces.list_spaces(conn, only_active=False)
        sp_active = [s for s in sp_all if s["active"]]
        scope = None if ctx.allowed_spaces == ["*"] else ctx.allowed_spaces
        counts = tasks.status_counts(conn, space_keys=scope)
        gs = knowledge.get_git_status(conn, ctx, root=self.service.knowledge_root)
        kpis = [("OPEN", counts.get("OPEN", 0)), ("READY", counts.get("READY", 0)),
                ("CLAIMED", counts.get("CLAIMED", 0) + counts.get("IN_PROGRESS", 0)),
                ("BLOCKED", counts.get("BLOCKED", 0)),
                ("COMPLETED", counts.get("COMPLETED", 0)),
                ("FAILED", counts.get("FAILED", 0))]
        kpi_html = "".join('<div class="kpi"><b>%d</b><span>%s</span></div>' % (v, k)
                           for k, v in kpis)
        gitb = ('<span class="badge ok">clean</span>' if gs["clean"]
                else '<span class="badge warn">uncommitted</span>')
        cards = [
            '<div class="card"><h2>Service</h2><p><span class="badge ok">active</span> '
            'brainy %s &middot; %d Tools &middot; localhost-only</p></div>'
            % (_esc(h["version"]), len(h["tools"])),
            '<div class="card"><h2>Tasks</h2><div class="grid">%s</div></div>' % kpi_html,
            '<div class="card"><h2>Spaces</h2><p><b>%d</b> active / %d total</p></div>'
            % (len(sp_active), len(sp_all)),
            '<div class="card"><h2>Knowledge (git)</h2><p>%s &middot; HEAD '
            '<span class=mono>%s</span></p></div>' % (gitb, _esc(gs["head"][:12])),
        ]
        # Dispatcher-Karte (Kill-Switch + Kennzahlen)
        ds = dispatcher.status(conn)
        run_badge = ('<span class="badge ok">RUNNING</span>' if ds["dispatcher_enabled"]
                     else '<span class="badge warn">PAUSED</span>')
        ctrl = ""
        if ctx.role == m.ADMIN:
            act = "pause" if ds["dispatcher_enabled"] else "resume"
            lbl = "Pause" if ds["dispatcher_enabled"] else "Resume"
            ctrl = ('<form class="inline" method="post" action="/admin/dispatcher/toggle">'
                    '<input type="hidden" name="csrf" value="%s"><input type="hidden" '
                    'name="action" value="%s"><button class="%s">%s Dispatcher</button>'
                    '</form>' % (_esc(ctx._csrf), act, "danger" if act == "pause" else
                                 "primary", lbl))
        fmb, swp, floor = ds.get("free_mb"), ds.get("swap_used_mb"), ds.get("min_free_mb")
        mem_style = ' style="color:var(--bad)"' if (fmb is not None and floor and fmb < floor) else ""
        cards.append('<div class="card"><h2>Dispatcher</h2><p>%s &nbsp; %s</p>'
                     '<div class="grid" style="margin-top:8px">'
                     '<div class="kpi"><b>%d</b><span>runnable READY</span></div>'
                     '<div class="kpi"><b>%d</b><span>active jobs</span></div>'
                     '<div class="kpi"><b>%d</b><span>failed jobs</span></div>'
                     '<div class="kpi"><b>%d</b><span>enabled agents</span></div>'
                     '<div class="kpi"><b%s>%s</b><span>RAM free (MB, floor %s)</span></div>'
                     '<div class="kpi"><b>%s</b><span>Swap used (MB)</span></div></div></div>'
                     % (run_badge, ctrl, ds["runnable_ready"], ds["active_jobs"],
                        ds["failed_jobs"], ds["enabled_agents"], mem_style,
                        "—" if fmb is None else fmb, floor,
                        "—" if swp is None else swp))
        # letzte Audit-Events (nur mit AUDIT_READ)
        if cap.check(conn, ctx, cap.AUDIT_READ):
            ev = audit.list_events(conn, limit=8)
            rows = "".join("<tr><td class=mono>%s</td><td>%s</td><td>%s</td>"
                           "<td class=mono>%s</td></tr>"
                           % (_esc(e["timestamp"][11:19]), _esc(_actor(conn, e["actor"])),
                              _esc(e["action"]), _esc(e["object_id"]))
                           for e in ev)
            cards.append('<div class="card"><h2>Recent audit events</h2><table><tr>'
                         '<th>Time</th><th>Actor</th><th>Action</th><th>Object</th></tr>'
                         '%s</table><p><a href="/admin/audit">All &rarr;</a></p></div>'
                         % rows)
        return _page("Dashboard", "<h1>Dashboard</h1>" + "".join(cards), ctx)

    def _tasks(self, conn, ctx, q):
        fstatus, fspace, fprio = q.get("status") or "", q.get("space") or "", q.get("priority") or ""
        readable = self._readable_spaces(conn, ctx)
        rows_out = []
        for sk in ([fspace] if fspace else readable):
            if sk not in readable:
                continue
            for t in tasks.list_tasks(conn, space=sk, status=(fstatus or None), limit=500):
                if fprio and t["priority"] != fprio:
                    continue
                rows_out.append((sk, t))
        rows_out.sort(key=lambda r: r[1]["created_at"], reverse=True)
        opt = lambda cur, vals: "".join(
            '<option%s>%s</option>' % (" selected" if v == cur else "", _esc(v)) for v in vals)
        can_create = any(cap.check(conn, ctx, cap.TASK_CREATE, s) for s in readable)
        create = ""
        if can_create:
            spopt = "".join('<option>%s</option>' % _esc(s) for s in readable
                            if cap.check(conn, ctx, cap.TASK_CREATE, s))
            agents = conn.execute("SELECT id,name FROM principals WHERE principal_type='AGENT' "
                                  "AND active=1 ORDER BY name").fetchall()
            aopt = '<option value="">— any —</option>' + "".join(
                '<option value="%s">%s</option>' % (a["id"], _esc(a["name"])) for a in agents)
            acopt = '<option value="">— (none) —</option>' + "".join(
                '<option>%s</option>' % _esc(a) for a in sorted(m.ACTION_CLASSES))
            create = ('<div class="card"><h2>New task</h2><form method="post" '
                      'action="/admin/tasks/create"><input type="hidden" name="csrf" '
                      'value="%s"><div class="filters"><label class="f">Space<select '
                      'name="space">%s</select></label><label class="f">Title<input '
                      'name="title" size="30" required></label><label class="f">Type'
                      '<select name="type">%s</select></label><label class="f">Prio'
                      '<select name="priority">%s</select></label><label class="f">Status'
                      '<select name="status"><option>OPEN</option><option>READY</option>'
                      '</select></label></div><div class="filters"><label class="f">'
                      'Execution-Mode<select name="execution_mode">%s</select></label>'
                      '<label class="f">Risk<select name="risk_level">%s</select></label>'
                      '<label class="f">Action-Class<select name="action_class">%s</select>'
                      '</label><label class="f">Preferred Agent<select name="preferred_agent">'
                      '%s</select></label><label class="f">Dependency (task_id)<input '
                      'name="dependency" size="16"></label><button class="primary">Create'
                      '</button></div><label class="f">Description<textarea '
                      'name="description" style="min-height:60px"></textarea></label>'
                      '<p class=muted style="font-size:12px">Brainy may automatically escalate the '
                      'mode per policy (e.g. PUBLISH/PAYMENT/DEPLOY → APPROVAL). '
                      'Downgrading is not possible.</p></form></div>'
                      % (_esc(ctx._csrf), spopt, opt("", sorted(m.TASK_TYPES)),
                         opt("P3", ["P1", "P2", "P3", "P4"]),
                         opt("REVIEW", ["AUTO", "REVIEW", "APPROVAL"]),
                         opt("MEDIUM", ["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
                         acopt, aopt))
        filt = ('<form class="filters" method="get" action="/admin/tasks">'
                '<label class="f">Status<select name="status"><option value="">all'
                '</option>%s</select></label><label class="f">Space<select name="space">'
                '<option value="">all</option>%s</select></label><label class="f">Prio'
                '<select name="priority"><option value="">all</option>%s</select></label>'
                '<button>Filter</button></form>'
                % (opt(fstatus, sorted(m.STATUSES)),
                   "".join('<option%s>%s</option>' % (" selected" if s == fspace else "",
                           _esc(s)) for s in readable),
                   opt(fprio, ["P1", "P2", "P3", "P4"])))
        trs = "".join(
            '<tr><td><a href="/admin/tasks/view?id=%s">%s</a></td><td>%s</td>'
            '<td>%s</td><td>%s</td><td>%s</td><td class=muted>%s</td></tr>'
            % (_esc(t["task_id"]), _esc((t["title"] or "")[:60]), _status_badge(t["status"]),
               _esc(sk), _esc(t["priority"]), _esc(t["type"]), _esc(t["created_at"][:16]))
            for sk, t in rows_out[:400])
        table = ('<div class="card"><table><tr><th>Title</th><th>Status</th><th>Space</th>'
                 '<th>Prio</th><th>Type</th><th>Created</th></tr>%s</table>'
                 '<p class=muted>%d Tasks</p></div>'
                 % (trs or '<tr><td colspan=6 class=muted>none</td></tr>', len(rows_out)))
        return _page("Tasks", "<h1>Tasks</h1>" + create + filt + table, ctx)

    def _task_govern(self, conn, ctx, form):
        tid = _need(form, "id")
        action = form.get("action")
        note = form.get("note") or None
        if action == "review_accept":
            tasks.review_task(conn, ctx, tid, "accept", note=note)
        elif action == "review_reject":
            tasks.review_task(conn, ctx, tid, "reject", note=note,
                              rework=bool(form.get("rework")))
        elif action == "approve":
            tasks.approve_task(conn, ctx, tid, note=note)
        elif action == "reject":
            tasks.reject_task(conn, ctx, tid, note=note)
        else:
            raise BrainyError("unknown governance action: %s" % action)
        return _redirect("/admin/tasks/view?id=" + tid)

    def _task_detail(self, conn, ctx, tid):
        if not tid:
            raise NotFound("task_id missing")
        t = tasks.get_task(conn, tid)
        if not t:
            raise NotFound(tid)
        sp = acl.get_space_row(conn, t["space_id"])
        sk = sp["key"] if sp else None
        if not cap.check(conn, ctx, cap.TASK_READ, sk):
            raise PermissionDenied("no read permission for this task")
        fields = [("Status", _status_badge(t["status"])), ("Space", _esc(sk)),
                  ("Type", _esc(t["type"])), ("Prio", _esc(t["priority"])),
                  ("Created", _esc(t["created_at"])), ("Updated", _esc(t["updated_at"])),
                  ("Claimed by", _esc(_actor(conn, t["claimed_by"]))),
                  ("Lease until", _esc(t["lease_until"])),
                  ("Result", _esc(t["result"])), ("Failure reason", _esc(t["failure_reason"]))]
        info = "".join("<tr><th>%s</th><td>%s</td></tr>" % (k, v) for k, v in fields)

        # --- Governance-Karte ---
        req, eff = t.get("execution_mode"), t.get("effective_execution_mode")
        esc = ""
        if eff and req and m.MODE_RANK.get(eff, 0) > m.MODE_RANK.get(req, 0):
            esc = ('<div class="flash err" style="margin:8px 0">Escalated: requested '
                   '<b>%s</b> → effective <b>%s</b>. Reason: %s</div>'
                   % (_esc(req), _esc(eff), _esc(t.get("policy_rule"))))
        deps = t.get("dependencies") or []
        deprows = []
        for d in deps:
            dt = tasks.get_task(conn, d)
            deprows.append("%s (%s)" % (_esc(d[:12]), _esc(dt["status"] if dt else "missing")))
        gfields = [
            ("Requested Mode", _esc(req)), ("Effective Mode", _esc(eff)),
            ("Risk", _esc(t.get("risk_level"))), ("Action-Class", _esc(t.get("action_class") or "—")),
            ("Approval required", "yes" if t.get("approval_required") else "no"),
            ("Policy rule", _esc(t.get("policy_rule") or "—")),
            ("Preferred Agent", _esc(_actor(conn, t.get("preferred_agent")) if t.get("preferred_agent") else "—")),
            ("Required Caps", _esc(", ".join(t.get("required_capabilities") or []) or "—")),
            ("Dependencies", ", ".join(deprows) if deprows else "—"),
            ("Reviewed by", _esc(_actor(conn, t.get("reviewed_by")) if t.get("reviewed_by") else "—")),
            ("Reviewed at", _esc(t.get("reviewed_at") or "—")),
            ("Review note", _esc(t.get("review_note") or "—")),
            ("Approved by", _esc(_actor(conn, t.get("approved_by")) if t.get("approved_by") else "—")),
            ("Approved at", _esc(t.get("approved_at") or "—")),
            ("Approval note", _esc(t.get("approval_note") or "—")),
        ]
        ginfo = "".join("<tr><th>%s</th><td>%s</td></tr>" % (k, v) for k, v in gfields)
        govcard = ('<div class="card"><h2>Governance</h2>%s<table>%s</table>%s</div>'
                   % (esc, ginfo, self._govern_actions(conn, ctx, t, sk)))

        # --- generische set_status-Aktionen (nur ohne aktiven Claim/Gate) ---
        actions = ""
        cur = t["status"]
        if cur in _ACTIVE_CLAIM:
            actions = ('<p class=muted>Active agent claim &mdash; status is only changed by '
                       'the agent (claim/complete/fail). No admin '
                       'override.</p>')
        elif cur not in (m.AWAITING_REVIEW, m.AWAITING_APPROVAL) \
                and cap.check(conn, ctx, cap.TASK_CREATE, sk):
            btns = []
            if m.READY in m.VALID_TRANSITIONS.get(cur, set()):
                lbl = "Release (READY)" if cur != m.BLOCKED else "Unblock (READY)"
                btns.append(_action_btn(ctx, tid, "ready" if cur != m.BLOCKED else "unblock", lbl))
            if m.BLOCKED in m.VALID_TRANSITIONS.get(cur, set()):
                btns.append(_action_btn(ctx, tid, "block", "Block", "danger"))
            if m.CANCELLED in m.VALID_TRANSITIONS.get(cur, set()):
                btns.append(_action_btn(ctx, tid, "cancel", "Cancel", "danger"))
            actions = '<div style="display:flex;gap:8px;flex-wrap:wrap">%s</div>' % "".join(btns)
        desc = ('<div class="card"><h2>Description</h2><pre style="background:#f2f5f8;'
                'color:#1c2530">%s</pre></div>' % _esc(t["description"] or "—"))
        body = ('<h1>%s</h1><p class=mono muted>%s</p>%s<div class="card"><table>%s</table>'
                '%s</div>%s'
                % (_esc(t["title"]), _esc(tid), govcard, info, actions, desc))
        return _page("Task", body, ctx)

    def _govern_actions(self, conn, ctx, t, sk):
        """Review-/Approval-Buttons nur fuer Berechtigte, nicht fuer den ausfuehrenden
        Owner (ausser ADMIN)."""
        cur = t["status"]
        is_self = (str(t.get("claimed_by")) == str(ctx.principal_id)
                   and ctx.role != m.ADMIN)
        if cur == m.AWAITING_REVIEW and cap.check(conn, ctx, cap.TASK_REVIEW, sk) and not is_self:
            return ('<div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">%s%s</div>'
                    % (_govern_btn(ctx, t["task_id"], "review_accept", "Review &amp; Accept",
                                   "primary"),
                       _govern_btn(ctx, t["task_id"], "review_reject", "Review &amp; Reject",
                                   "danger")))
        if cur == m.AWAITING_APPROVAL and cap.check(conn, ctx, cap.TASK_APPROVE, sk) \
                and not is_self:
            return ('<div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">%s%s</div>'
                    % (_govern_btn(ctx, t["task_id"], "approve", "Approve", "primary"),
                       _govern_btn(ctx, t["task_id"], "reject", "Reject", "danger")))
        if cur in (m.AWAITING_REVIEW, m.AWAITING_APPROVAL):
            reason = "self-approval not allowed" if is_self else "no review/approve permission"
            return '<p class=muted style="margin-top:8px">Waiting at gate — %s.</p>' % _esc(reason)
        return ""

    def _knowledge(self, conn, ctx, root):
        docs = knowledge.list_documents(conn, ctx, root=root)
        search = ('<form class="filters" method="get" action="/admin/knowledge/search">'
                  '<label class="f">Full-text search<input name="q" size="40" '
                  'placeholder="Term ..."></label><button>Search</button></form>')
        trs = "".join(
            '<tr><td><a href="/admin/knowledge/view?path=%s">%s</a></td><td>%s</td>'
            '<td class=muted>%s</td><td class=muted>%s</td><td><a href="/admin/knowledge/'
            'history?path=%s">History</a></td></tr>'
            % (urllib.parse.quote(d["path"]), _esc(d["path"]), _esc(d["space"]),
               _esc((d["title"] or "")[:60]), _esc(d["git_status"]),
               urllib.parse.quote(d["path"]))
            for d in docs)
        table = ('<div class="card"><table><tr><th>Path</th><th>Space</th><th>Title</th>'
                 '<th>Git</th><th></th></tr>%s</table><p class=muted>%d documents</p></div>'
                 % (trs or '<tr><td colspan=5 class=muted>none</td></tr>', len(docs)))
        return _page("Knowledge", "<h1>Knowledge</h1>" + search + table, ctx)

    def _doc_view(self, conn, ctx, path, root):
        if not path:
            raise NotFound("path missing")
        doc = knowledge.get_document(conn, ctx, path, root=root)
        can_edit = cap.check(conn, ctx, cap.KNOWLEDGE_WRITE, doc["space"])
        edit = ('<a class="btn" href="/admin/knowledge/edit?path=%s">Edit</a> '
                % urllib.parse.quote(doc["path"])) if can_edit else \
               '<span class=muted>(no write permission)</span> '
        body = ('<h1>%s</h1><p class=muted>Space %s &middot; HEAD <span class=mono>%s</span> '
                '&middot; %s<a class="btn" href="/admin/knowledge/history?path=%s">History'
                '</a></p><div class="card"><pre style="background:#f2f5f8;color:#1c2530;'
                'white-space:pre-wrap">%s</pre></div>'
                % (_esc(doc["path"]), _esc(doc["space"]), _esc(doc["git_commit"][:12]), edit,
                   urllib.parse.quote(doc["path"]), _esc(doc["content"])))
        return _page("Document", body, ctx)

    def _doc_search(self, conn, ctx, query, root):
        hits = knowledge.search_knowledge(conn, ctx, query, root=root) if query else []
        trs = "".join(
            '<tr><td><a href="/admin/knowledge/view?path=%s">%s</a></td><td>%s</td>'
            '<td>%d</td><td class=muted>%s</td></tr>'
            % (urllib.parse.quote(h["path"]), _esc(h["path"]), _esc(h["space"]),
               h["count"], _esc(h["snippet"][:120]))
            for h in hits)
        body = ('<h1>Search</h1><form class="filters" method="get" '
                'action="/admin/knowledge/search"><label class="f">Term<input name="q" '
                'size="40" value="%s"></label><button>Search</button></form>'
                '<div class="card"><table><tr><th>Path</th><th>Space</th><th>Hits</th>'
                '<th>Context</th></tr>%s</table><p class=muted>%d hits</p></div>'
                % (_esc(query), trs or '<tr><td colspan=4 class=muted>none</td></tr>',
                   len(hits)))
        return _page("Search", body, ctx)

    def _doc_history(self, conn, ctx, path, root):
        if not path:
            raise NotFound("path missing")
        hist = knowledge.get_document_history(conn, ctx, path, root=root)
        trs = []
        for i, c in enumerate(hist):
            diff = ""
            if i + 1 < len(hist):
                diff = ('<a href="/admin/knowledge/diff?path=%s&from=%s&to=%s">Diff</a>'
                        % (urllib.parse.quote(path), hist[i + 1]["commit"], c["commit"]))
            trs.append('<tr><td class=mono>%s</td><td class=muted>%s</td><td>%s</td>'
                       '<td>%s</td><td>%s</td></tr>'
                       % (_esc(c["commit"][:10]), _esc(c["timestamp"][:19]),
                          _esc(c["author"]), _esc(c["message"][:60]), diff))
        body = ('<h1>History</h1><p class=mono muted>%s</p><div class="card"><table><tr>'
                '<th>Commit</th><th>Time</th><th>Author</th><th>Message</th><th></th></tr>'
                '%s</table></div><p><a href="/admin/knowledge/view?path=%s">&larr; Document'
                '</a></p>' % (_esc(path), "".join(trs), urllib.parse.quote(path)))
        return _page("History", body, ctx)

    def _doc_diff(self, conn, ctx, path, frm, to, root):
        if not (path and frm and to):
            raise NotFound("path/from/to missing")
        d = knowledge.get_document_diff(conn, ctx, path, frm, to, root=root)
        body = ('<h1>Diff</h1><p class=mono muted>%s &middot; %s..%s</p><div class="card">'
                '<pre>%s</pre></div><p><a href="/admin/knowledge/history?path=%s">&larr; '
                'History</a></p>' % (_esc(path), _esc(frm[:10]), _esc(to[:10]),
                                      _color_diff(d), urllib.parse.quote(path)))
        return _page("Diff", body, ctx)

    def _doc_edit(self, conn, ctx, path, root):
        if not path:
            raise NotFound("path missing")
        doc = knowledge.get_document(conn, ctx, path, root=root)
        cap.require(conn, ctx, cap.KNOWLEDGE_WRITE, doc["space"])
        body = ('<h1>Edit</h1><p class=muted>%s &middot; base commit <span class=mono>'
                '%s</span> (optimistic concurrency). Secret guard active; the commit goes '
                'through the knowledge service.</p><div class="card"><form method="post" '
                'action="/admin/knowledge/save"><input type="hidden" name="csrf" value="%s">'
                '<input type="hidden" name="path" value="%s"><input type="hidden" '
                'name="expected_git_commit" value="%s"><textarea name="content">%s</textarea>'
                '<div class="filters" style="margin-top:10px"><label class="f">'
                'Commit message<input name="commit_message" size="46" required></label>'
                '<button class="primary">Save</button><a class="btn" '
                'href="/admin/knowledge/view?path=%s">Cancel</a></div></form></div>'
                % (_esc(doc["path"]), _esc(doc["git_commit"][:12]), _esc(ctx._csrf),
                   _esc(doc["path"]), _esc(doc["git_commit"]), _esc(doc["content"]),
                   urllib.parse.quote(doc["path"])))
        return _page("Edit", body, ctx)

    def _spaces(self, conn, ctx):
        sps = spaces.list_spaces(conn, only_active=False)
        cards = []
        for s in sps:
            badge = ('<span class="badge ok">active</span>' if s["active"]
                     else '<span class="badge bad">inactive</span>')
            aclrows = ""
            if cap.check(conn, ctx, cap.SPACE_READ, s["key"]) or ctx.role == m.ADMIN:
                for a in acl.list_acl(conn, s["key"]):
                    p = acl.get_principal(conn, a["principal_id"])
                    caps = ",".join(c for c in m.ALL_CAPS if a.get(c))
                    aclrows += ('<tr><td>%s</td><td class=muted>%s</td></tr>'
                                % (_esc(p["name"] if p else a["principal_id"]),
                                   _esc(caps or "—")))
            acltab = ('<table><tr><th>Principal</th><th>Permissions</th></tr>%s</table>'
                      % aclrows) if aclrows else '<p class=muted>no ACL entries</p>'
            cards.append('<div class="card"><h2>%s %s</h2><p class=muted>%s</p>%s</div>'
                         % (_esc(s["key"]), badge, _esc(s["name"]), acltab))
        return _page("Spaces", "<h1>Spaces</h1>" + "".join(cards), ctx)

    def _agents(self, conn, ctx):
        rows = agents.list_agents(conn)
        is_admin = ctx.role == m.ADMIN
        trs = ""
        for a in rows:
            en = ('<span class="badge ok">enabled</span>' if a["enabled"]
                  else '<span class="badge warn">disabled</span>')
            btn = ""
            if is_admin:
                act = "disable" if a["enabled"] else "enable"
                btn = ('<form class="inline" method="post" action="/admin/agents/toggle">'
                       '<input type="hidden" name="csrf" value="%s"><input type="hidden" '
                       'name="agent_name" value="%s"><input type="hidden" name="action" '
                       'value="%s"><button>%s</button></form>'
                       % (_esc(ctx._csrf), _esc(a["agent_name"]), act, act))
            trs += ('<tr><td>%s</td><td class=muted>%s</td><td>%s</td><td>%s</td>'
                    '<td>%d</td><td class=muted>%s</td><td class=muted>%s</td><td>%s</td></tr>'
                    % (_esc(a["agent_name"]), _esc(a["principal_name"]),
                       _esc(a["worker_type"]), en, a["max_concurrency"],
                       _esc(a["status"]), _esc((a["last_seen"] or "—")[:19] if a["last_seen"]
                                               else "—"), btn))
        body = ('<h1>Agents</h1><p class=muted>Worker registry. Capabilities/spaces come '
                'from the principal ACL. No secrets.</p><div class="card"><table><tr>'
                '<th>Agent</th><th>Principal</th><th>Worker</th><th>Enabled</th>'
                '<th>Concurrency</th><th>Status</th><th>Last seen</th><th></th></tr>%s'
                '</table></div>' % (trs or '<tr><td colspan=8 class=muted>none</td></tr>'))
        return _page("Agents", body, ctx)

    def _jobs(self, conn, ctx, q):
        jobs = dispatcher.list_jobs(conn, task_id=q.get("task") or None,
                                    status=q.get("status") or None, limit=200)
        trs = ""
        for j in jobs:
            trs += ('<tr><td class=mono><a href="/admin/tasks/view?id=%s">%s</a></td>'
                    '<td class=mono>%s</td><td>%s</td><td>%s</td><td>%d</td>'
                    '<td class=muted>%s</td><td class=muted>%s</td><td class=muted>%s</td></tr>'
                    % (urllib.parse.quote(j["task_id"]), _esc(j["task_id"][:10]),
                       _esc(_actor(conn, j["agent_principal_id"])), _esc(j["worker_type"]),
                       _status_badge(j["status"]), j["attempt"],
                       _esc((j["started_at"] or "—")[:19] if j["started_at"] else "—"),
                       _esc(j["error_summary"] or "—"),
                       _esc((j["result_ref"] or "—")[:40])))
        body = ('<h1>Execution Jobs</h1><p class=muted>Executions (without dispatch_token). '
                'Status QUEUED/STARTING/RUNNING/SUCCEEDED/FAILED/TIMED_OUT/CANCELLED.</p>'
                '<div class="card"><table><tr><th>Task</th><th>Agent</th><th>Worker</th>'
                '<th>Status</th><th>Attempt</th><th>Start</th><th>Error</th><th>Result</th>'
                '</tr>%s</table><p class=muted>%d Jobs</p></div>'
                % (trs or '<tr><td colspan=8 class=muted>none</td></tr>', len(jobs)))
        return _page("Jobs", body, ctx)

    def _principals(self, conn, ctx):
        cap.require(conn, ctx, cap.PRINCIPAL_MANAGE)   # ADMIN
        rows = conn.execute("SELECT id, principal_type, name, role, active, created_at "
                            "FROM principals ORDER BY id").fetchall()
        trs = "".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>'
                      '<td class=muted>%s</td></tr>'
                      % (r["id"], _esc(r["name"]), _esc(r["principal_type"]), _esc(r["role"]),
                         ('<span class="badge ok">active</span>' if r["active"]
                          else '<span class="badge bad">inactive</span>'),
                         _esc(r["created_at"][:16])) for r in rows)
        body = ('<h1>Principals</h1><p class=muted>No token values &mdash; metadata only.'
                '</p><div class="card"><table><tr><th>ID</th><th>Name</th><th>Type</th>'
                '<th>Role</th><th>Status</th><th>Created</th></tr>%s</table></div>' % trs)
        return _page("Principals", body, ctx)

    def _tokens(self, conn, ctx):
        cap.require(conn, ctx, cap.TOKEN_MANAGE)   # ADMIN
        rows = toks.list_all_service_tokens(conn)
        trs = ""
        for r in rows:
            p = acl.get_principal(conn, r["principal_id"])
            state = ('<span class="badge bad">revoked</span>' if r["revoked_at"] or
                     not r["active"] else '<span class="badge ok">active</span>')
            trs += ('<tr><td class=mono>%s</td><td>%s</td><td class=muted>%s</td><td>%s</td>'
                    '<td class=muted>%s</td><td class=muted>%s</td><td class=muted>%s</td>'
                    '</tr>'
                    % (_esc(r["token_id"]), _esc(p["name"] if p else r["principal_id"]),
                       _esc(r["description"] or "—"), state, _esc((r["created_at"] or "")[:16]),
                       _esc((r["expires_at"] or "—")[:16] if r["expires_at"] else "—"),
                       _esc((r["last_used_at"] or "—")[:16] if r["last_used_at"] else "—")))
        body = ('<h1>Service Tokens</h1><p class=muted>Token ID + metadata only. '
                'Token hash/plaintext are never displayed.</p><div class="card">'
                '<table><tr><th>Token ID</th><th>Principal</th><th>Description</th>'
                '<th>Status</th><th>Created</th><th>Expires</th><th>Last used</th>'
                '</tr>%s</table></div>' % trs)
        return _page("Tokens", body, ctx)

    def _audit(self, conn, ctx, q):
        cap.require(conn, ctx, cap.AUDIT_READ)   # ADMIN/EDITOR
        factor, faction, fspace = q.get("actor") or "", q.get("action") or "", q.get("space") or ""
        sid = None
        if fspace:
            sp = spaces.get_space(conn, fspace)
            sid = sp["id"] if sp else -1
        ev = audit.list_events(conn, action=(faction or None),
                               actor=(factor or None), space_id=sid, limit=200)
        trs = "".join('<tr><td class=mono>%s</td><td>%s</td><td>%s</td><td>%s</td>'
                      '<td class=mono>%s</td></tr>'
                      % (_esc(e["timestamp"][:19]), _esc(_actor(conn, e["actor"])),
                         _esc(e["action"]), _esc(e["object_type"]), _esc(e["object_id"]))
                      for e in ev)
        spopt = "".join('<option%s>%s</option>' % (" selected" if s["key"] == fspace else "",
                        _esc(s["key"])) for s in spaces.list_spaces(conn, only_active=False))
        filt = ('<form class="filters" method="get" action="/admin/audit">'
                '<label class="f">Actor<input name="actor" value="%s" size="10"></label>'
                '<label class="f">Action<input name="action" value="%s" size="16"></label>'
                '<label class="f">Space<select name="space"><option value="">all</option>'
                '%s</select></label><button>Filter</button></form>'
                % (_esc(factor), _esc(faction), spopt))
        body = ('<h1>Audit</h1><p class=muted>Append-only &mdash; read-only. No '
                'editing/deletion possible.</p>%s<div class="card"><table><tr>'
                '<th>Time</th><th>Actor</th><th>Action</th><th>Type</th><th>Object</th></tr>'
                '%s</table><p class=muted>%d Events</p></div>'
                % (filt, trs or '<tr><td colspan=5 class=muted>none</td></tr>', len(ev)))
        return _page("Audit", body, ctx)

    # ---- Helpers ---------------------------------------------------------
    def _readable_spaces(self, conn, ctx):
        if ctx.allowed_spaces == ["*"]:
            return [s["key"] for s in spaces.list_spaces(conn, only_active=True)]
        return list(ctx.allowed_spaces)


def _need(form, key):
    v = form.get(key)
    if v is None or v == "":
        raise BrainyError("required field missing: %s" % key)
    return v


def _actor(conn, actor):
    if actor is None:
        return "—"
    try:
        p = acl.get_principal(conn, int(actor))
        if p:
            return p["name"]
    except (ValueError, TypeError):
        pass
    return str(actor)


_BADGE = {"OPEN": "", "READY": "ok", "CLAIMED": "warn", "IN_PROGRESS": "warn",
          "BLOCKED": "bad", "COMPLETED": "ok", "FAILED": "bad", "CANCELLED": ""}


def _status_badge(s):
    return '<span class="badge %s">%s</span>' % (_BADGE.get(s, ""), _esc(s))


def _action_btn(ctx, tid, action, label, cls=""):
    return ('<form class="inline" method="post" action="/admin/tasks/action">'
            '<input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" '
            'value="%s"><input type="hidden" name="action" value="%s">'
            '<button class="%s">%s</button></form>'
            % (_esc(ctx._csrf), _esc(tid), _esc(action), _esc(cls), _esc(label)))


def _govern_btn(ctx, tid, action, label, cls=""):
    return ('<form class="inline" method="post" action="/admin/tasks/govern">'
            '<input type="hidden" name="csrf" value="%s"><input type="hidden" name="id" '
            'value="%s"><input type="hidden" name="action" value="%s">'
            '<input name="note" placeholder="Note (optional)" size="16" '
            'style="margin-right:4px"><button class="%s">%s</button></form>'
            % (_esc(ctx._csrf), _esc(tid), _esc(action), _esc(cls), label))


def _color_diff(text):
    out = []
    for line in (text or "").splitlines():
        cls = ""
        if line.startswith("+") and not line.startswith("+++"):
            cls = "diff-add"
        elif line.startswith("-") and not line.startswith("---"):
            cls = "diff-del"
        out.append('<span class="%s">%s</span>' % (cls, _esc(line)) if cls else _esc(line))
    return "\n".join(out) or "(no changes)"
