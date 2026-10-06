"""Brainy MCP-/Remote-Service (Phase D).

Transport: **JSON-over-HTTP** ueber die Python-stdlib (`http.server`) — dependency-frei,
localhost-only. Der Tool-Layer (`dispatch`) ist transport-unabhaengig und getrennt
testbar; ein echter MCP-Protokoll-Adapter kann in Phase F duenn darueber gelegt werden.

Sicherheit: Bearer-Service-Token (Phase C) -> AuthContext; Rate-Limit; ACL/Allowlist
aus Phase A/B/C. KEINE Shell/FS-API, KEINE SQL-Schnittstelle, KEINE Tracebacks nach aussen,
KEIN Token/Secret in Logs/Audit.
"""
import json
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import (__version__, acl, agents, audit, auth, capabilities as cap, config, db,
               dispatcher, knowledge, oauth, proposals, tasks, telegram)
from .errors import (AuthFailed, BrainyError, ClaimConflict, Conflict, InvalidState,
                     NotFound, PermissionDenied, SecretDetected, StaleToken)
from .paths import PathNotAllowed
from .ratelimit import RateLimiter

# --- MCP (Streamable HTTP, JSON-RPC 2.0) ---
MCP_PROTOCOL_VERSION = "2025-06-18"
_WRITE_TOOLS = {"write_document", "append_document"}

# Server-Instructions (Phase O7): werden vom MCP-Client in den System-Prompt uebernommen und
# gelten so fuer Claude Web/Desktop/Mobile ueber den Connector. Zentrale "Brainy-first"- und
# "Selective Auto-Capture"-Policy. Governance/ACL/Secret-Guard bleiben serverseitig massgeblich.
MCP_INSTRUCTIONS = (
    "Brainy is the PRIMARY source of knowledge and work (Single Source of Truth).\n"
    "BRAINY-FIRST: For statements/questions involving project, tool, system or work context, "
    "search Brainy FIRST (search_knowledge / list_documents) and prefer reading existing documents "
    "(get_document) instead of answering primarily from model/chat memory. If Brainy contains "
    "nothing relevant, say so explicitly; if something is ambiguous, ask instead of guessing. "
    "If Brainy and memory disagree, Brainy counts as the current SoT (unless marked as outdated) "
    "- make the contradiction visible, do not silently overwrite it.\n"
    "SELECTIVE AUTO-CAPTURE: Automatically write back information of lasting relevance - "
    "decisions, requirements, changes, bugs/error states, architecture/configuration "
    "decisions, open items/todos, firm preferences/project rules, important operational info. "
    "Prefer targeted updates/additions to the most fitting EXISTING document (write_document "
    "with expected_git_commit for optimistic concurrency; append_document only for shared/todo.md) "
    "instead of new files/duplicates; reuse the existing structure/terminology and the most fitting space.\n"
    "DO NOT save automatically: small talk, fleeting ideas without a decision, speculation, "
    "brainstorming fragments, trivial one-off questions, anything HYPOTHETICAL ('maybe/could/what "
    "if'), things phrased as questions, statements that cannot be clearly assigned or that contradict "
    "an existing SoT without a clearly stated new decision -> ask first in that case. "
    "NEVER store secrets/tokens/passwords. Do not store uncertain information as fact; instead ask "
    "or explicitly mark it as 'unconfirmed / to be verified'.\n"
    "TRANSPARENCY: After saving automatically, BRIEFLY report what was changed and in which Brainy "
    "path/space (no long change report). Details: shared/conventions.md.\n"
    "Security: ACL/governance/secret guard/path allowlist are enforced server-side; no shell/FS/SQL."
)

# Fehler -> (standardisierter code, HTTP-Status)
_ERROR_MAP = [
    (AuthFailed, ("unauthorized", 401)),
    (PermissionDenied, ("forbidden", 403)),
    (NotFound, ("not_found", 404)),
    (StaleToken, ("invalid_claim", 409)),
    (ClaimConflict, ("conflict", 409)),
    (Conflict, ("conflict", 409)),
    (SecretDetected, ("invalid_request", 400)),
    (PathNotAllowed, ("invalid_request", 400)),
    (InvalidState, ("invalid_request", 400)),
    (BrainyError, ("invalid_request", 400)),
]


def _map_error(exc):
    for typ, res in _ERROR_MAP:
        if isinstance(exc, typ):
            return res
    return ("internal_error", 500)


def _req(params, key):
    if key not in params or params[key] in (None, ""):
        raise BrainyError("required field missing: %s" % key)
    return params[key]


# ---- Tool-Wrapper: (conn, ctx, params, root) -> JSON-serialisierbares Result ----
def _t_list_spaces(conn, ctx, p, root):
    return {"spaces": knowledge.list_spaces(conn, ctx, root=root)}


def _t_list_documents(conn, ctx, p, root):
    return {"documents": knowledge.list_documents(conn, ctx, space=p.get("space"), root=root)}


def _t_get_document(conn, ctx, p, root):
    return knowledge.get_document(conn, ctx, _req(p, "path"), root=root)


def _t_search_knowledge(conn, ctx, p, root):
    return {"hits": knowledge.search_knowledge(conn, ctx, _req(p, "query"),
                                               space=p.get("space"),
                                               limit=int(p.get("limit", 50)), root=root)}


def _t_write_document(conn, ctx, p, root):
    return knowledge.write_document(conn, ctx, _req(p, "path"), _req(p, "content"),
                                    p.get("expected_git_commit"), _req(p, "commit_message"),
                                    root=root)


def _t_append_document(conn, ctx, p, root):
    return knowledge.append_document(conn, ctx, _req(p, "path"), _req(p, "text"),
                                     p.get("expected_git_commit"), _req(p, "commit_message"),
                                     root=root)


def _t_propose_write(conn, ctx, p, root):
    """VORSCHLAG einer Knowledge-Aenderung (kein direkter Write). Legt einen
    PENDING-Vorschlag an und schickt best-effort eine Telegram-Freigabe-Anfrage.
    Der echte Write passiert erst nach Owner-Freigabe (apply_proposal)."""
    prop = proposals.create_proposal(conn, ctx, _req(p, "path"), _req(p, "content"),
                                     _req(p, "commit_message"),
                                     expected_git_commit=p.get("expected_git_commit"),
                                     root=root)
    notified = False
    try:
        mid = telegram.send_approval_request(prop, root=root)
        if mid:
            conn.execute("UPDATE write_proposals SET tg_message_id=? WHERE proposal_id=?",
                         (mid, prop["proposal_id"]))
            conn.commit()
            notified = True
    except Exception:
        notified = False
    return {"proposal_id": prop["proposal_id"], "status": "pending_approval",
            "space": prop["space"], "path": prop["path"], "notified": notified}


def _t_list_tasks(conn, ctx, p, root):
    status, typ, limit = p.get("status"), p.get("type"), int(p.get("limit", 200))
    space = p.get("space")
    if space:
        if not cap.check(conn, ctx, cap.TASK_READ, space):
            raise PermissionDenied("no read permission in space %s" % space)
        return {"tasks": tasks.list_tasks(conn, space=space, status=status, type=typ, limit=limit)}
    # ohne Space: nur Tasks aus lesbaren Spaces (ADMIN: alle)
    if ctx.allowed_spaces == ["*"]:
        return {"tasks": tasks.list_tasks(conn, status=status, type=typ, limit=limit)}
    out = []
    for s in ctx.allowed_spaces:
        out += tasks.list_tasks(conn, space=s, status=status, type=typ, limit=limit)
    return {"tasks": out}


def _t_get_task(conn, ctx, p, root):
    t = tasks.get_task(conn, _req(p, "task_id"))
    if not t:
        raise NotFound(p.get("task_id"))
    sp = acl.get_space_row(conn, t["space_id"])
    space_key = sp["key"] if sp else None
    if not cap.check(conn, ctx, cap.TASK_READ, space_key):
        raise PermissionDenied("no read permission for task %s" % t["task_id"])
    return t


def _t_create_task(conn, ctx, p, root):
    return tasks.create_task(conn, ctx, _req(p, "space"), _req(p, "title"),
                             type=p.get("type", "chore"), priority=p.get("priority", "P3"),
                             description=p.get("description", ""),
                             target_ref=p.get("target_ref"), source_sot=p.get("source_sot"),
                             tags=p.get("tags"), status=p.get("status", "OPEN"),
                             execution_mode=p.get("execution_mode"),
                             risk_level=p.get("risk_level"),
                             action_class=p.get("action_class"),
                             dependencies=p.get("dependencies"),
                             preferred_agent=p.get("preferred_agent"),
                             required_capabilities=p.get("required_capabilities"))


def _t_claim_task(conn, ctx, p, root):
    return tasks.claim_task(conn, ctx, _req(p, "task_id"),
                            lease_seconds=int(p.get("lease_seconds", 900)))


def _t_renew_claim(conn, ctx, p, root):
    return tasks.renew_claim(conn, ctx, _req(p, "task_id"), _req(p, "claim_token"),
                             lease_seconds=int(p.get("lease_seconds", 900)))


def _t_release_task(conn, ctx, p, root):
    return tasks.release_task(conn, ctx, _req(p, "task_id"), _req(p, "claim_token"))


def _t_complete_task(conn, ctx, p, root):
    return tasks.complete_task(conn, ctx, _req(p, "task_id"), _req(p, "claim_token"),
                               result=p.get("result"), result_refs=p.get("result_refs"))


def _t_fail_task(conn, ctx, p, root):
    return tasks.fail_task(conn, ctx, _req(p, "task_id"), _req(p, "claim_token"),
                           reason=p.get("reason", ""))


def _t_review_task(conn, ctx, p, root):
    return tasks.review_task(conn, ctx, _req(p, "task_id"), _req(p, "decision"),
                             note=p.get("note"), rework=bool(p.get("rework")))


def _t_approve_task(conn, ctx, p, root):
    return tasks.approve_task(conn, ctx, _req(p, "task_id"), note=p.get("note"))


def _t_reject_task(conn, ctx, p, root):
    return tasks.reject_task(conn, ctx, _req(p, "task_id"), note=p.get("note"))


def _t_list_runnable_tasks(conn, ctx, p, root):
    return {"tasks": tasks.list_runnable_tasks_for_agent(
        conn, ctx, limit=int(p.get("limit", 200)))}


def _agent_public(a):
    return {k: a.get(k) for k in ("agent_name", "principal_id", "principal_name",
            "worker_type", "enabled", "max_concurrency", "status", "last_seen")}


def _t_list_agents(conn, ctx, p, root):
    return {"agents": [_agent_public(a) for a in agents.list_agents(conn)]}


def _t_get_agent_status(conn, ctx, p, root):
    a = agents.get_agent(conn, _req(p, "agent_name"))
    if not a:
        raise NotFound(p.get("agent_name"))
    return _agent_public(a)


def _t_list_execution_jobs(conn, ctx, p, root):
    return {"jobs": dispatcher.list_jobs(conn, task_id=p.get("task_id"),
                                         status=p.get("status"),
                                         limit=int(p.get("limit", 100)))}


def _t_get_execution_job(conn, ctx, p, root):
    j = dispatcher.get_job(conn, _req(p, "job_id"))
    if not j:
        raise NotFound(p.get("job_id"))
    return j


def _t_enable_agent(conn, ctx, p, root):
    return agents.set_enabled(conn, ctx, _req(p, "agent_name"), True)


def _t_disable_agent(conn, ctx, p, root):
    return agents.set_enabled(conn, ctx, _req(p, "agent_name"), False)


def _t_pause_dispatcher(conn, ctx, p, root):
    return dispatcher.pause_dispatcher(conn, ctx)


def _t_resume_dispatcher(conn, ctx, p, root):
    return dispatcher.resume_dispatcher(conn, ctx)


TOOLS = {
    "list_spaces": _t_list_spaces,
    "list_documents": _t_list_documents,
    "get_document": _t_get_document,
    "search_knowledge": _t_search_knowledge,
    "write_document": _t_write_document,
    "append_document": _t_append_document,
    "propose_write": _t_propose_write,
    "list_tasks": _t_list_tasks,
    "get_task": _t_get_task,
    "create_task": _t_create_task,
    "claim_task": _t_claim_task,
    "renew_claim": _t_renew_claim,
    "release_task": _t_release_task,
    "complete_task": _t_complete_task,
    "fail_task": _t_fail_task,
    "review_task": _t_review_task,
    "approve_task": _t_approve_task,
    "reject_task": _t_reject_task,
    "list_runnable_tasks": _t_list_runnable_tasks,
    "list_agents": _t_list_agents,
    "get_agent_status": _t_get_agent_status,
    "list_execution_jobs": _t_list_execution_jobs,
    "get_execution_job": _t_get_execution_job,
    "enable_agent": _t_enable_agent,
    "disable_agent": _t_disable_agent,
    "pause_dispatcher": _t_pause_dispatcher,
    "resume_dispatcher": _t_resume_dispatcher,
}

# Nur ADMIN: globale Dispatcher-/Agent-Controls (Sichtbarkeit + Durchsetzung).
_ADMIN_TOOLS = {"enable_agent", "disable_agent", "pause_dispatcher", "resume_dispatcher"}

# OAuth-Scope pro Tool. Tools OHNE Eintrag sind fuer OAuth-Clients NICHT verfuegbar
# (Governance-/Agent-/Admin-Tools bleiben Menschen/Service-Token vorbehalten). Die ACL
# wird zusaetzlich immer geprueft — Scopes umgehen die ACL nie.
_OAUTH_TOOL_SCOPE = {
    "list_spaces": "brainy:knowledge:read", "list_documents": "brainy:knowledge:read",
    "get_document": "brainy:knowledge:read", "search_knowledge": "brainy:knowledge:read",
    "write_document": "brainy:knowledge:write", "append_document": "brainy:knowledge:write",
    "propose_write": "brainy:knowledge:write",
    "list_tasks": "brainy:tasks:read", "get_task": "brainy:tasks:read",
    "list_runnable_tasks": "brainy:tasks:read",
    "create_task": "brainy:tasks:write", "claim_task": "brainy:tasks:write",
    "renew_claim": "brainy:tasks:write", "release_task": "brainy:tasks:write",
    "complete_task": "brainy:tasks:write", "fail_task": "brainy:tasks:write",
}


def _scope_allows(ctx, tool):
    """True, wenn der (ggf. OAuth-)Kontext dieses Tool per Scope nutzen darf.
    Service-Token/intern (scopes=None) -> keine Scope-Grenze. OAuth -> nur gemappte
    Tools und nur mit passendem Scope."""
    scopes = getattr(ctx, "scopes", None)
    if scopes is None:
        return True
    need = _OAUTH_TOOL_SCOPE.get(tool)
    return need is not None and need in scopes


def _err(code, message):
    return {"ok": False, "error": {"code": code, "message": message}}


# ---------------------------------------------------------------- MCP schemas
_S_STR = {"type": "string"}
TOOL_SCHEMAS = {
    "list_spaces": {"type": "object", "properties": {}},
    "list_documents": {"type": "object", "properties": {"space": _S_STR}},
    "get_document": {"type": "object", "properties": {"path": _S_STR}, "required": ["path"]},
    "search_knowledge": {"type": "object", "properties": {
        "query": _S_STR, "space": _S_STR, "limit": {"type": "integer"}}, "required": ["query"]},
    "write_document": {"type": "object", "properties": {
        "path": _S_STR, "content": _S_STR, "expected_git_commit": _S_STR,
        "commit_message": _S_STR}, "required": ["path", "content", "commit_message"]},
    "append_document": {"type": "object", "properties": {
        "path": _S_STR, "text": _S_STR, "expected_git_commit": _S_STR,
        "commit_message": _S_STR}, "required": ["path", "text", "commit_message"]},
    "propose_write": {"type": "object", "properties": {
        "path": _S_STR, "content": _S_STR, "expected_git_commit": _S_STR,
        "commit_message": _S_STR}, "required": ["path", "content", "commit_message"]},
    "list_tasks": {"type": "object", "properties": {
        "space": _S_STR, "status": _S_STR, "type": _S_STR, "limit": {"type": "integer"}}},
    "get_task": {"type": "object", "properties": {"task_id": _S_STR}, "required": ["task_id"]},
    "create_task": {"type": "object", "properties": {
        "space": _S_STR, "title": _S_STR, "type": _S_STR, "priority": _S_STR,
        "description": _S_STR, "target_ref": _S_STR, "status": _S_STR,
        "execution_mode": _S_STR, "risk_level": _S_STR, "action_class": _S_STR,
        "dependencies": {"type": "array"}, "preferred_agent": _S_STR,
        "required_capabilities": {"type": "array"}}, "required": ["space", "title"]},
    "review_task": {"type": "object", "properties": {
        "task_id": _S_STR, "decision": _S_STR, "note": _S_STR,
        "rework": {"type": "boolean"}}, "required": ["task_id", "decision"]},
    "approve_task": {"type": "object", "properties": {
        "task_id": _S_STR, "note": _S_STR}, "required": ["task_id"]},
    "reject_task": {"type": "object", "properties": {
        "task_id": _S_STR, "note": _S_STR}, "required": ["task_id"]},
    "list_runnable_tasks": {"type": "object", "properties": {"limit": {"type": "integer"}}},
    "list_agents": {"type": "object", "properties": {}},
    "get_agent_status": {"type": "object", "properties": {"agent_name": _S_STR},
                         "required": ["agent_name"]},
    "list_execution_jobs": {"type": "object", "properties": {
        "task_id": _S_STR, "status": _S_STR, "limit": {"type": "integer"}}},
    "get_execution_job": {"type": "object", "properties": {"job_id": _S_STR},
                          "required": ["job_id"]},
    "enable_agent": {"type": "object", "properties": {"agent_name": _S_STR},
                     "required": ["agent_name"]},
    "disable_agent": {"type": "object", "properties": {"agent_name": _S_STR},
                      "required": ["agent_name"]},
    "pause_dispatcher": {"type": "object", "properties": {}},
    "resume_dispatcher": {"type": "object", "properties": {}},
    "claim_task": {"type": "object", "properties": {
        "task_id": _S_STR, "lease_seconds": {"type": "integer"}}, "required": ["task_id"]},
    "renew_claim": {"type": "object", "properties": {
        "task_id": _S_STR, "claim_token": _S_STR}, "required": ["task_id", "claim_token"]},
    "release_task": {"type": "object", "properties": {
        "task_id": _S_STR, "claim_token": _S_STR}, "required": ["task_id", "claim_token"]},
    "complete_task": {"type": "object", "properties": {
        "task_id": _S_STR, "claim_token": _S_STR, "result": _S_STR,
        "result_refs": {"type": "array"}}, "required": ["task_id", "claim_token"]},
    "fail_task": {"type": "object", "properties": {
        "task_id": _S_STR, "claim_token": _S_STR, "reason": _S_STR},
        "required": ["task_id", "claim_token"]},
}

_TOOL_DESC = {
    "list_spaces": "List visible knowledge spaces.",
    "list_documents": "List canonical Markdown documents (optional space).",
    "get_document": "Read a knowledge document (path allowlist, ACL).",
    "search_knowledge": "Search knowledge case-insensitively (ACL, optional space).",
    "write_document": "Write a knowledge document (git commit; ACL/secret guard).",
    "append_document": "Append to an allowed target (e.g. shared/todo.md).",
    "propose_write": "PROPOSE a change to a knowledge document (no direct write). "
                     "The owner approves via Telegram; only then is it committed. "
                     "Use this when you do not have direct write permission.",
    "list_tasks": "List tasks of a readable space.",
    "get_task": "Read a task.",
    "create_task": "Create a task.",
    "claim_task": "Claim a task atomically (lease + claim_token).",
    "renew_claim": "Extend the lease.",
    "release_task": "Release your own claim.",
    "complete_task": "Complete a task — governance-gated (AUTO->COMPLETED, "
                     "REVIEW->AWAITING_REVIEW, APPROVAL->AWAITING_APPROVAL).",
    "fail_task": "Mark a task as failed (idempotent).",
    "review_task": "Decide the review gate (decision=accept|reject). Requires review permission; "
                   "no self-review.",
    "approve_task": "Approve the approval gate (-> APPROVED). Requires approve permission; "
                    "no self-approval.",
    "reject_task": "Reject at the approval gate (-> REJECTED). Requires approve permission.",
    "list_runnable_tasks": "Tasks runnable by this principal (READY, deps satisfied, "
                           "ACL, required_capabilities, preferred_agent).",
    "list_agents": "List the agent registry (no secrets).",
    "get_agent_status": "Status of an agent.",
    "list_execution_jobs": "List execution jobs (without dispatch_token).",
    "get_execution_job": "Read an execution job (without dispatch_token).",
    "enable_agent": "Enable an agent (ADMIN).",
    "disable_agent": "Disable an agent (ADMIN).",
    "pause_dispatcher": "Pause the dispatcher globally (ADMIN, kill switch).",
    "resume_dispatcher": "Resume the dispatcher globally (ADMIN).",
}


# MCP-Tool-Annotations (Spec 2025-06-18): read-only vs. veraendernd/destruktiv.
# Hilft Clients (z.B. ChatGPT) zu verstehen, welche Tools lesen vs. schreiben.
_READ_TOOLS = {"list_spaces", "list_documents", "get_document", "search_knowledge",
               "list_tasks", "get_task", "list_runnable_tasks", "list_agents",
               "get_agent_status", "list_execution_jobs", "get_execution_job"}
_TOOL_ANNOT = {
    "create_task": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
    "claim_task": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
    "renew_claim": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
    "release_task": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
    "complete_task": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
    "fail_task": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
    "review_task": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
    "approve_task": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
    "reject_task": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
    "write_document": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False},
    "append_document": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False},
    "propose_write": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
}

# Governance-Tools werden nur eingeblendet, wenn der Principal das Recht IRGENDWO hat.
_REVIEW_TOOLS = {"review_task"}
_APPROVE_TOOLS = {"approve_task", "reject_task"}


def _annotations(name):
    if name in _READ_TOOLS:
        return {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
    return _TOOL_ANNOT.get(name, {"readOnlyHint": False})


def _has_cap_anywhere(conn, ctx, column):
    if getattr(ctx, "role", None) == "ADMIN":
        return True
    r = conn.execute("SELECT 1 FROM space_acl WHERE principal_id=? AND %s=1 LIMIT 1" % column,
                     (ctx.principal_id,)).fetchone()
    return r is not None


def _can_write_anywhere(conn, ctx):
    return _has_cap_anywhere(conn, ctx, "can_write")


def _mcp_tools_list(conn, ctx):
    """Principal-abhaengig: Write-/Governance-Tools nur, wenn ACL/Rolle es erlaubt."""
    writes_ok = _can_write_anywhere(conn, ctx)
    review_ok = _has_cap_anywhere(conn, ctx, "can_review")
    approve_ok = _has_cap_anywhere(conn, ctx, "can_approve")
    out = []
    is_admin = getattr(ctx, "role", None) == "ADMIN"
    for name in sorted(TOOLS):
        if not _scope_allows(ctx, name):        # OAuth: nur gemappte Tools im Scope
            continue
        if name in _WRITE_TOOLS and not writes_ok:
            continue
        if name in _REVIEW_TOOLS and not review_ok:
            continue
        if name in _APPROVE_TOOLS and not approve_ok:
            continue
        if name in _ADMIN_TOOLS and not is_admin:
            continue
        out.append({"name": name, "description": _TOOL_DESC.get(name, name),
                    "inputSchema": TOOL_SCHEMAS.get(name, {"type": "object"}),
                    "annotations": _annotations(name)})
    return out


def _rpc_result(mid, result):
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _rpc_error(mid, code, message):
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


class BrainyService:
    def __init__(self, db_path, knowledge_root, rate_limit="240/60"):
        self.db_path = db_path
        self.knowledge_root = knowledge_root
        self.limiter = RateLimiter(rate_limit)

    def _conn(self):
        return db.connect(self.db_path)

    def health(self):
        return {"status": "ok", "service": "brainy", "version": __version__,
                "tools": sorted(TOOLS)}

    def handle(self, method, path, auth_header, body_bytes):
        """Transport-unabhaengiger Kern. Rueckgabe: (http_status:int, obj:dict)."""
        if method == "GET" and path == "/health":
            return 200, self.health()
        if path != "/rpc" or method != "POST":
            return 404, _err("not_found", "unknown route")
        try:
            payload = json.loads(body_bytes or b"{}")
            if not isinstance(payload, dict):
                raise ValueError()
        except Exception:
            return 400, _err("invalid_request", "body is not a JSON object")
        tool = payload.get("tool")
        params = payload.get("params") or {}
        if not isinstance(params, dict):
            return 400, _err("invalid_request", "params must be an object")

        conn = self._conn()
        try:
            # Auth (nur Header, nie Query)
            try:
                ctx = self._auth(conn, auth_header)
            except AuthFailed:
                return 401, _err("unauthorized", "authentication failed")
            # Rate-Limit
            key = ctx.token_id or ("pid:%s" % ctx.principal_id)
            if not self.limiter.allow(key):
                audit.log(conn, ctx.principal_id, "rate_limited", "mcp", tool, None,
                          {"tool": tool}, commit=True)
                return 429, _err("rate_limited", "too many requests")
            # Dispatch
            if tool not in TOOLS:
                return 400, _err("invalid_request", "unknown tool")
            if not _scope_allows(ctx, tool):
                return 403, _err("forbidden", "no scope/access for this tool")
            t0 = time.time()
            try:
                result = TOOLS[tool](conn, ctx, params, self.knowledge_root)
            except tuple(t for t, _ in _ERROR_MAP) as e:
                code, status = _map_error(e)
                if status == 403:
                    audit.log(conn, ctx.principal_id, "mcp_tool_denied", "mcp", tool, None,
                              {"tool": tool, "code": code}, commit=True)
                return status, _err(code, str(e)[:200])
            except Exception:
                # KEIN Traceback nach aussen
                audit.log(conn, ctx.principal_id, "mcp_tool_called", "mcp", tool, None,
                          {"tool": tool, "status": "error"}, commit=True)
                return 500, _err("internal_error", "internal error")
            audit.log(conn, ctx.principal_id, "mcp_tool_called", "mcp", tool, None,
                      {"tool": tool, "status": "ok", "space": params.get("space"),
                       "ms": int((time.time() - t0) * 1000)}, commit=True)
            return 200, {"ok": True, "result": result}
        finally:
            conn.close()

    def _auth(self, conn, auth_header):
        if not auth_header or not str(auth_header).lower().startswith("bearer "):
            raise AuthFailed("missing_bearer")
        token = str(auth_header)[7:].strip()
        return auth.authenticate_bearer(conn, token)   # Service-Token ODER OAuth; raises AuthFailed

    # ---- MCP (Streamable HTTP, JSON-RPC 2.0). Rueckgabe: (status, content_type, bytes) ----
    def handle_mcp(self, http_method, auth_header, body_bytes):
        if http_method == "GET":
            # Kein server-initiiertes SSE noetig -> 405 (spec-konform).
            return 405, "text/plain", b"SSE stream not offered"
        if http_method != "POST":
            return 405, "text/plain", b"method not allowed"
        try:
            msg = json.loads(body_bytes or b"{}")
            if not isinstance(msg, dict):
                raise ValueError()
        except Exception:
            return 400, "application/json", json.dumps(_rpc_error(None, -32700, "parse error")).encode()
        method = msg.get("method")
        mid = msg.get("id")
        params = msg.get("params") or {}
        is_notification = "id" not in msg

        conn = self._conn()
        try:
            try:
                ctx = self._auth(conn, auth_header)
            except AuthFailed:
                if is_notification:
                    return 401, "application/json", b""
                return 401, "application/json", json.dumps(
                    _rpc_error(mid, -32001, "unauthorized")).encode()

            # Notifications (z.B. notifications/initialized) -> 202, kein Body
            if is_notification:
                return 202, "application/json", b""

            if method == "initialize":
                result = {"protocolVersion": MCP_PROTOCOL_VERSION,
                          "capabilities": {"tools": {"listChanged": False}},
                          "serverInfo": {"name": "brainy", "version": __version__},
                          "instructions": MCP_INSTRUCTIONS}
                return 200, "application/json", json.dumps(_rpc_result(mid, result)).encode()
            if method == "ping":
                return 200, "application/json", json.dumps(_rpc_result(mid, {})).encode()
            if method == "tools/list":
                return 200, "application/json", json.dumps(
                    _rpc_result(mid, {"tools": _mcp_tools_list(conn, ctx)})).encode()
            if method == "tools/call":
                name = params.get("name")
                args = params.get("arguments") or {}
                if name not in TOOLS:
                    return 200, "application/json", json.dumps(_rpc_result(mid, {
                        "content": [{"type": "text", "text": "unknown tool: %s" % name}],
                        "isError": True})).encode()
                if not _scope_allows(ctx, name):
                    audit.log(conn, ctx.principal_id, "mcp_tool_denied", "mcp", name, None,
                              {"tool": name, "via": "mcp", "code": "forbidden_scope"}, commit=True)
                    return 200, "application/json", json.dumps(_rpc_result(mid, {
                        "content": [{"type": "text", "text": json.dumps(
                            {"error": "forbidden", "message": "no scope/access for this tool"})}],
                        "isError": True})).encode()
                key = ctx.token_id or ("pid:%s" % ctx.principal_id)
                if not self.limiter.allow(key):
                    audit.log(conn, ctx.principal_id, "rate_limited", "mcp", name, None,
                              {"tool": name, "via": "mcp"}, commit=True)
                    return 429, "application/json", json.dumps(
                        _rpc_error(mid, -32000, "rate_limited")).encode()
                t0 = time.time()
                try:
                    res = TOOLS[name](conn, ctx, args, self.knowledge_root)
                    audit.log(conn, ctx.principal_id, "mcp_tool_called", "mcp", name, None,
                              {"tool": name, "via": "mcp", "status": "ok",
                               "space": args.get("space"),
                               "ms": int((time.time() - t0) * 1000)}, commit=True)
                    return 200, "application/json", json.dumps(_rpc_result(mid, {
                        "content": [{"type": "text",
                                     "text": json.dumps(res, ensure_ascii=False)}],
                        "isError": False})).encode()
                except tuple(t for t, _ in _ERROR_MAP) as e:
                    code, status = _map_error(e)
                    if status == 403:
                        audit.log(conn, ctx.principal_id, "mcp_tool_denied", "mcp", name,
                                  None, {"tool": name, "via": "mcp", "code": code}, commit=True)
                    else:
                        audit.log(conn, ctx.principal_id, "mcp_tool_called", "mcp", name,
                                  None, {"tool": name, "via": "mcp", "status": code}, commit=True)
                    # Tool-Fehler MCP-idiomatisch als isError-Result (Claude sieht den Code)
                    return 200, "application/json", json.dumps(_rpc_result(mid, {
                        "content": [{"type": "text", "text": json.dumps(
                            {"error": code, "message": str(e)[:200]})}],
                        "isError": True})).encode()
                except Exception:
                    audit.log(conn, ctx.principal_id, "mcp_tool_called", "mcp", name, None,
                              {"tool": name, "via": "mcp", "status": "error"}, commit=True)
                    return 200, "application/json", json.dumps(_rpc_result(mid, {
                        "content": [{"type": "text", "text": json.dumps(
                            {"error": "internal_error"})}], "isError": True})).encode()
            return 200, "application/json", json.dumps(
                _rpc_error(mid, -32601, "method not found: %s" % method)).encode()
        finally:
            conn.close()


    # ---- Telegram-Webhook: Approve/Reject fuer Write-Vorschlaege ----
    def handle_telegram(self, http_method, secret_header, body_bytes):
        """Eigene Auth in ZWEI Schichten: (1) Telegram-secret_token-Header (timing-safe)
        und (2) Owner-Chat-ID. Rueckgabe: (status, content_type, bytes). Nach bestandener
        Auth immer 200, damit Telegram das Update nicht endlos wiederholt."""
        if http_method != "POST":
            return 405, "text/plain", b"method not allowed"
        if not telegram.verify_webhook_secret(secret_header):
            return 401, "application/json", b'{"ok":false}'
        try:
            update = json.loads(body_bytes or b"{}")
            if not isinstance(update, dict):
                raise ValueError()
        except Exception:
            return 400, "application/json", b'{"ok":false}'
        cb = telegram.parse_callback(update)
        if not cb:
            return 200, "application/json", b'{"ok":true}'   # nur Callback-Updates relevant
        if not telegram.is_owner(cb["from_id"]):
            telegram.answer_callback(cb["callback_query_id"], "Not authorized.")
            return 200, "application/json", b'{"ok":true}'
        conn = self._conn()
        try:
            approver = acl.get_principal_by_name(conn, config.TELEGRAM_APPROVER_PRINCIPAL)
            if not approver:
                telegram.answer_callback(cb["callback_query_id"], "Approver principal missing.")
                return 200, "application/json", b'{"ok":true}'
            ctx = auth.context_for_principal(conn, approver["id"])
            pid_ = cb["proposal_id"]
            try:
                if cb["action"] == "ap":
                    res = proposals.apply_proposal(conn, ctx, pid_, root=self.knowledge_root)
                    txt = "Approved ✅ (%s)" % (str(res.get("result_commit") or "?")[:10])
                elif cb["action"] == "rj":
                    proposals.reject_proposal(conn, ctx, pid_)
                    txt = "Rejected ❌"
                else:
                    txt = "Unknown action."
            except Exception as e:
                txt = "Error: %s" % (str(e)[:120])
            telegram.answer_callback(cb["callback_query_id"], txt)
            telegram.edit_message(cb.get("chat_id"), cb.get("message_id"),
                                  "Proposal %s: %s" % (pid_, txt))
            return 200, "application/json", b'{"ok":true}'
        finally:
            conn.close()

    # ---- OAuth-2.1-Authorization-Server (Discovery/DCR/Token/Revoke) ----
    def _oj(self, status, obj, extra=None):
        data = json.dumps(obj).encode("utf-8")
        headers = [("Cache-Control", "no-store")] + list(extra or [])
        return status, "application/json", headers, data

    def handle_oauth(self, method, path, query, body_bytes):
        base = config.PUBLIC_BASE_URL.rstrip("/")
        if method == "GET" and path in ("/.well-known/oauth-protected-resource",
                                        "/.well-known/oauth-protected-resource/mcp"):
            return self._oj(200, oauth.protected_resource_metadata(base))
        if method == "GET" and path in ("/.well-known/oauth-authorization-server",
                                        "/.well-known/oauth-authorization-server/mcp"):
            return self._oj(200, oauth.authorization_server_metadata(base))
        if method != "POST":
            return self._oj(404, {"error": "not_found"})
        if not self.limiter.allow("oauth:" + path):
            return self._oj(429, {"error": "temporarily_unavailable",
                                  "error_description": "rate limited"})
        conn = self._conn()
        try:
            if path == "/oauth/register":
                data = _parse_json_or_form(body_bytes)
                sc = data.get("scope")
                if isinstance(sc, list):
                    sc = " ".join(sc)
                try:
                    cl = oauth.register_client(
                        conn, data.get("client_name"), data.get("redirect_uris"),
                        scope=sc, grant_types=data.get("grant_types"),
                        token_endpoint_auth_method=data.get("token_endpoint_auth_method", "none"))
                except oauth.OAuthError as e:
                    return self._oj(400, {"error": e.error, "error_description": e.description})
                out = oauth.client_public(cl)
                out["client_id_issued_at"] = int(time.time())
                return self._oj(201, out)
            form = _parse_form(body_bytes)
            if path == "/oauth/token":
                gt = form.get("grant_type")
                try:
                    if gt == "authorization_code":
                        res = oauth.exchange_code(conn, form.get("code"), form.get("client_id"),
                                                  form.get("redirect_uri"), form.get("code_verifier"))
                    elif gt == "refresh_token":
                        res = oauth.refresh_token(conn, form.get("refresh_token"),
                                                  form.get("client_id"))
                    else:
                        return self._oj(400, {"error": "unsupported_grant_type"})
                    return self._oj(200, res)
                except oauth.OAuthError as e:
                    return self._oj(e.status, {"error": e.error, "error_description": e.description})
            if path == "/oauth/revoke":
                oauth.revoke(conn, form.get("token"))     # RFC 7009: immer 200
                return self._oj(200, {})
            return self._oj(404, {"error": "not_found"})
        finally:
            conn.close()


def _parse_form(body_bytes):
    q = urllib.parse.parse_qs((body_bytes or b"").decode("utf-8", "replace"),
                              keep_blank_values=True)
    return {k: v[0] for k, v in q.items()}


def _parse_json_or_form(body_bytes):
    raw = (body_bytes or b"").decode("utf-8", "replace").strip()
    if raw.startswith("{"):
        try:
            return json.loads(raw)
        except Exception:
            pass
    return _parse_form(body_bytes)


# ---------------------------------------------------------------- HTTP-Transport
def _is_oauth_api_path(path):
    return (path.startswith("/.well-known/oauth")
            or path in ("/oauth/token", "/oauth/register", "/oauth/revoke"))


def _is_web_path(path):
    return (path == "/" or path == "/admin" or path.startswith("/admin/")
            or path == "/oauth/authorize")


def make_handler(service, web=None):
    class Handler(BaseHTTPRequestHandler):
        server_version = "brainy/" + __version__
        protocol_version = "HTTP/1.1"

        def _run(self, method):
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length) if length else b""
            full = self.path
            qidx = full.find("?")
            path = full[:qidx] if qidx >= 0 else full
            query = full[qidx + 1:] if qidx >= 0 else ""
            headers = []
            if path == "/mcp":
                status, ctype, data = service.handle_mcp(
                    method, self.headers.get("Authorization"), body)
                if status == 401:
                    # RFC 9728: Client zur Protected-Resource-Metadata leiten (OAuth-Discovery).
                    base = config.PUBLIC_BASE_URL.rstrip("/")
                    headers.append(("WWW-Authenticate",
                                    'Bearer resource_metadata='
                                    '"%s/.well-known/oauth-protected-resource/mcp"' % base))
            elif path == "/telegram/webhook":
                status, ctype, data = service.handle_telegram(
                    method, self.headers.get("X-Telegram-Bot-Api-Secret-Token"), body)
            elif _is_oauth_api_path(path):
                status, ctype, headers, data = service.handle_oauth(method, path, query, body)
            elif web is not None and _is_web_path(path):
                status, ctype, headers, data = web.handle(
                    method, path, query, self.headers.get("Cookie"), body)
            else:
                status, obj = service.handle(method, path,
                                             self.headers.get("Authorization"), body)
                ctype, data = "application/json", json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if data and method != "HEAD":
                self.wfile.write(data)

        def do_GET(self):
            self._run("GET")

        def do_POST(self):
            self._run("POST")

        def log_message(self, *a):
            return  # keine Request-Logs (koennten Header/Token enthalten)

    return Handler


def run_server(service, host, port, allow_public=False, web=None):
    from . import config
    if not config.is_localhost(host) and not allow_public:
        raise BrainyError("bind host %s is not localhost and ALLOW_PUBLIC!=1 "
                          "-> refusing to start (localhost-only)" % host)
    httpd = ThreadingHTTPServer((host, port), make_handler(service, web=web))
    print("brainy service listening on http://%s:%d (localhost-only=%s)"
          % (host, port, config.is_localhost(host)), flush=True)
    httpd.serve_forever()
