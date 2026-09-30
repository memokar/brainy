"""Knowledge-Service (Phase B): kontrollierter Zugriff auf /opt/brainy-knowledge.

- list_spaces / list_documents / get_document / search_knowledge (read)
- write_document / append_document (kontrollierte Git-Writes, Optimistic Concurrency,
  Secret-Guard, nur Ziel-Datei staged, atomarer Ersatz, Rollback bei Commit-Fehler)
- get_git_status / get_git_diff / get_document_history / get_document_diff (read-only)

ACL kommt aus Phase A (acl.check_permission). KEINE generische Filesystem-API,
KEIN HTTP/MCP hier. Knowledge-Root zentral in paths.KNOWLEDGE_ROOT.
"""
import os
import re

from . import acl
from . import audit
from . import gitops
from . import models as m
from . import paths
from .errors import Conflict, NotFound, PermissionDenied, SecretDetected
from .paths import PathNotAllowed
from .util import now_iso, pid

# Explizit erlaubte Append-Ziele (nicht pauschal jede SoT).
ALLOWED_APPEND = {"shared/todo.md"}

# Secret-Guard: mutmassliche echte Geheimniswerte. Bewusst NICHT jedes Vorkommen
# des Wortes "token" — nur Muster mit tatsaechlichem Wert.
_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bshpat_[A-Za-z0-9]{10,}"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}"),
    re.compile(r"\bEAA[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}"),
    re.compile(r"(?i)(password|passwort|secret|api[_-]?key|client_secret|access_token"
               r"|token)\s*[:=]\s*[\"'][^\"'\s]{12,}[\"']"),
]

_IGNORE_DIRS = {".git"}


def scan_secrets(content):
    """Gibt den Namen des ersten getroffenen Musters zurueck oder None.
    KEIN Secret-Wert wird zurueckgegeben/geloggt."""
    for pat in _SECRET_PATTERNS:
        if pat.search(content or ""):
            return pat.pattern[:40]
    return None


# ---------------------------------------------------------------- Helpers
def _root(root):
    return paths.knowledge_root(root)


def _is_canonical_rel(rel):
    try:
        paths.normalize_rel(rel)
        return rel.endswith(".md")
    except PathNotAllowed:
        return False


def _iter_docs(root):
    r = _root(root)
    for base, dirs, files in os.walk(r):
        dirs[:] = [d for d in dirs if d not in _IGNORE_DIRS and not d.startswith(".")]
        for f in files:
            rel = os.path.relpath(os.path.join(base, f), r).replace("\\", "/")
            if _is_canonical_rel(rel):
                yield rel


def _title_of(abs_path):
    try:
        with open(abs_path, "r", encoding="utf-8") as fh:
            head = fh.read(4000)
    except Exception:
        return None
    md = re.search(r"^description:\s*\"?(.+?)\"?\s*$", head, re.MULTILINE)
    if md:
        return md.group(1)[:160]
    h1 = re.search(r"^#\s+(.+)$", head, re.MULTILINE)
    return h1.group(1).strip()[:160] if h1 else None


def _can_read(conn, principal_id, space):
    return acl.check_permission(conn, principal_id, space, m.CAP_READ)


# ---------------------------------------------------------------- Read
def list_spaces(conn, principal_id, root=None):
    principal_id = pid(principal_id)
    out = []
    for sp in list(paths.ALLOWED_TOP):
        if _can_read(conn, principal_id, sp):
            out.append(sp)
    return out


def list_documents(conn, principal_id, space=None, root=None):
    principal_id = pid(principal_id)
    r = _root(root)
    res = []
    for rel in sorted(_iter_docs(root)):
        sp = paths.space_for_path(rel)
        if space and sp != space:
            continue
        if not _can_read(conn, principal_id, sp):
            continue
        abs_path = os.path.join(r, rel)
        st = os.stat(abs_path)
        res.append({
            "path": rel,
            "space": sp,
            "name": os.path.basename(rel),
            "title": _title_of(abs_path),
            "modified_at": now_iso_from_mtime(st.st_mtime),
            "git_status": _file_git_status(r, rel),
        })
    audit.log(conn, principal_id, "knowledge_read", "knowledge", "list_documents",
              None, {"space": space, "count": len(res)}, commit=True)
    return res


def now_iso_from_mtime(ts):
    import datetime as dt
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat(timespec="seconds")


def _file_git_status(root, rel):
    try:
        line = gitops._git(root, "status", "--porcelain", "--", rel).strip()
    except Exception:
        return "?"
    return line[:2] if line else "clean"


def get_document(conn, principal_id, path, root=None):
    principal_id = pid(principal_id)
    try:
        rel, abs_path = paths.resolve(path, root=root)
    except PathNotAllowed as e:
        audit.log(conn, principal_id, "knowledge_write_rejected_path", "knowledge",
                  str(path), None, {"reason": str(e)[:120], "op": "read"}, commit=True)
        raise
    sp = paths.space_for_path(rel)
    if not _can_read(conn, principal_id, sp):
        raise PermissionDenied("kein Leserecht im space %s" % sp)
    if not os.path.exists(abs_path):
        raise NotFound(rel)
    with open(abs_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    audit.log(conn, principal_id, "knowledge_read", "knowledge", rel,
              None, {"bytes": len(content)}, commit=True)
    return {"path": rel, "space": sp, "content": content,
            "git_commit": gitops.head_commit(_root(root))}


def search_knowledge(conn, principal_id, query, space=None, limit=50, root=None):
    principal_id = pid(principal_id)
    r = _root(root)
    q = (query or "").lower()
    hits = []
    if q:
        for rel in _iter_docs(root):
            sp = paths.space_for_path(rel)
            if space and sp != space:
                continue
            if not _can_read(conn, principal_id, sp):
                continue
            try:
                with open(os.path.join(r, rel), "r", encoding="utf-8") as fh:
                    text = fh.read()
            except Exception:
                continue
            low = text.lower()
            count = low.count(q)
            if count:
                idx = low.find(q)
                start = max(0, idx - 40)
                snippet = text[start:idx + len(q) + 60].replace("\n", " ")
                hits.append({"path": rel, "space": sp, "count": count,
                             "snippet": snippet.strip()})
    hits.sort(key=lambda h: h["count"], reverse=True)
    hits = hits[:limit]
    audit.log(conn, principal_id, "knowledge_search", "knowledge", None,
              None, {"space": space, "results": len(hits)}, commit=True)
    return hits


# ---------------------------------------------------------------- Write
def write_document(conn, principal_id, path, content, expected_git_commit,
                   commit_message, root=None):
    principal_id = pid(principal_id)
    r = _root(root)
    # 1) Pfad validieren (mit Audit bei Verstoss)
    try:
        rel, abs_path = paths.resolve(path, root=root)
    except PathNotAllowed as e:
        audit.log(conn, principal_id, "knowledge_write_rejected_path", "knowledge",
                  str(path), None, {"reason": str(e)[:120]}, commit=True)
        raise
    sp = paths.space_for_path(rel)
    # 2) Permission
    acl.require(conn, principal_id, sp, m.CAP_WRITE)
    audit.log(conn, principal_id, "knowledge_write_started", "knowledge", rel, None,
              {"space": sp}, commit=True)
    # 3) Repo muss clean sein (keine fremden uncommitted Aenderungen ueberschreiben)
    if not gitops.is_clean(r):
        audit.log(conn, principal_id, "knowledge_write_rejected_conflict", "knowledge",
                  rel, None, {"reason": "repo_not_clean"}, commit=True)
        raise Conflict("Repo hat uncommittete Aenderungen -> Write abgelehnt")
    # 4) Optimistic Concurrency
    head = gitops.head_commit(r)
    if expected_git_commit and expected_git_commit != head:
        audit.log(conn, principal_id, "knowledge_write_rejected_conflict", "knowledge",
                  rel, None, {"reason": "stale_expected_commit", "head": head}, commit=True)
        raise Conflict("expected_git_commit veraltet (HEAD=%s)" % head)
    # 5) Secret-Guard
    hit = scan_secrets(content)
    if hit:
        audit.log(conn, principal_id, "knowledge_write_rejected_secret", "knowledge",
                  rel, None, {"pattern": hit}, commit=True)   # KEIN Secret-Wert
        raise SecretDetected("mutmassliches Secret im Content -> Write abgelehnt")
    # 6) validieren (leichtgewichtig: UTF-8, nicht leer)
    if not isinstance(content, str) or content.strip() == "":
        raise Conflict("leerer/ungueltiger Content")
    # 7) temporaer schreiben + atomar ersetzen
    tmp = abs_path + ".brainy.tmp"
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.replace(tmp, abs_path)
    # 8) NUR Ziel-Datei stagen + committen; bei Fehler Rollback
    try:
        gitops.add_path(r, rel)
        commit = gitops.commit_path(r, rel, commit_message,
                                    author_name=_actor_name(conn, principal_id))
    except Exception as e:
        gitops.restore_to_head(r, rel)   # Datei + Index sauber zuruecksetzen
        audit.log(conn, principal_id, "knowledge_write_rejected_conflict", "knowledge",
                  rel, None, {"reason": "commit_failed", "err": str(e)[:120]}, commit=True)
        raise
    audit.log(conn, principal_id, "knowledge_write_committed", "knowledge", rel, None,
              {"commit": commit}, commit=True)
    return {"path": rel, "commit": commit}


def append_document(conn, principal_id, path, text, expected_git_commit,
                    commit_message, root=None):
    principal_id = pid(principal_id)
    rel = paths.normalize_rel(path)
    if rel not in ALLOWED_APPEND:
        audit.log(conn, principal_id, "knowledge_write_rejected_path", "knowledge",
                  rel, None, {"reason": "append_not_allowed"}, commit=True)
        raise PermissionDenied("append nur fuer erlaubte Ziele: %s" % sorted(ALLOWED_APPEND))
    r = _root(root)
    _, abs_path = paths.resolve(rel, root=root)
    current = ""
    if os.path.exists(abs_path):
        with open(abs_path, "r", encoding="utf-8") as fh:
            current = fh.read()
    if current and not current.endswith("\n"):
        current += "\n"
    neu = current + text + ("\n" if not text.endswith("\n") else "")
    return write_document(conn, principal_id, rel, neu, expected_git_commit,
                          commit_message, root=root)


def _actor_name(conn, principal_id):
    p = acl.get_principal(conn, principal_id)
    return (p or {}).get("name") or ("principal-%s" % principal_id)


# ---------------------------------------------------------------- Git read-only
def get_git_status(conn, principal_id, root=None):
    r = _root(root)
    return {"head": gitops.head_commit(r), "clean": gitops.is_clean(r),
            "porcelain": gitops.status_porcelain(r)}


def get_git_diff(conn, principal_id, path=None, root=None):
    r = _root(root)
    if path:
        rel, _ = paths.resolve(path, root=root)
        return gitops.diff_file(r, rel)
    return gitops._git(r, "diff")


def get_document_history(conn, principal_id, path, limit=20, root=None):
    principal_id = pid(principal_id)
    rel, _ = paths.resolve(path, root=root)
    sp = paths.space_for_path(rel)
    if not _can_read(conn, principal_id, sp):
        raise PermissionDenied("kein Leserecht im space %s" % sp)
    return gitops.log_file(_root(root), rel, limit)


def get_document_diff(conn, principal_id, path, from_commit, to_commit, root=None):
    principal_id = pid(principal_id)
    rel, _ = paths.resolve(path, root=root)
    sp = paths.space_for_path(rel)
    if not _can_read(conn, principal_id, sp):
        raise PermissionDenied("kein Leserecht im space %s" % sp)
    return gitops.diff_between(_root(root), rel, from_commit, to_commit)
