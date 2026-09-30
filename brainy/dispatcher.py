"""Agent-Dispatcher / Execution-Runtime (Phase O2).

Alles laeuft ueber Brainy Tasks + Claims + Audit — KEINE Agent-zu-Agent-Magie.
Governance (AUTO/REVIEW/APPROVAL) bleibt SoT in orchestration.py; hier NUR Auswahl,
atomarer Claim, Execution-Job-Verwaltung, Lease/Timeout-Recovery, Retry, Kill-Switch.

Sicherheit: globaler Kill-Switch (settings.dispatcher_enabled, Default FALSE), per-Agent
`enabled`, Concurrency-Limit, EIN aktiver Job pro Task (DB-Constraint), keine kritische
Aktion vor Approval, keine Secrets in Logs/Job-Views.
"""
import sqlite3
import time
import uuid

from . import acl, agents, audit, config, models as m, settings, tasks
from . import capabilities as cap
from . import workers as wk
from .errors import ClaimConflict, PermissionDenied
from .util import iso_plus, now_iso, pid

ACTIVE_JOB = ("QUEUED", "STARTING", "RUNNING")
FAILED_JOB = ("FAILED", "TIMED_OUT")
# Lease MUSS groesser als der Hard-Timeout jedes registrierten Workers
# sein, sonst raeumt recover_timeouts einen noch laufenden Job vorzeitig ab.
DEFAULT_LEASE = 1800
DEFAULT_POLL = 5
DISPATCH_ACTOR = "dispatcher"


# ---------------------------------------------------------------- Job-Helfer
def _job_row(conn, job_id):
    r = conn.execute("SELECT * FROM execution_jobs WHERE job_id=?", (job_id,)).fetchone()
    return dict(r) if r else None


def _public_job(row):
    """Job-Ansicht OHNE internen dispatch_token (nie in UI/MCP)."""
    if row is None:
        return None
    d = dict(row)
    d.pop("dispatch_token", None)
    return d


def get_job(conn, job_id):
    return _public_job(_job_row(conn, job_id))


def list_jobs(conn, task_id=None, status=None, agent_principal_id=None, limit=200):
    sql = "SELECT * FROM execution_jobs WHERE 1=1"
    args = []
    if task_id:
        sql += " AND task_id=?"; args.append(task_id)
    if status:
        sql += " AND status=?"; args.append(status)
    if agent_principal_id is not None:
        sql += " AND agent_principal_id=?"; args.append(int(agent_principal_id))
    sql += " ORDER BY created_at DESC LIMIT ?"; args.append(limit)
    return [_public_job(dict(r)) for r in conn.execute(sql, args)]


def _has_active_job(conn, task_id):
    r = conn.execute(
        "SELECT 1 FROM execution_jobs WHERE task_id=? AND status IN ('QUEUED','STARTING',"
        "'RUNNING') LIMIT 1", (task_id,)).fetchone()
    return r is not None


def _attempts(conn, task_id):
    return conn.execute(
        "SELECT COUNT(*) c FROM execution_jobs WHERE task_id=? AND status IN ('FAILED',"
        "'TIMED_OUT')", (task_id,)).fetchone()["c"]


def _last_failure_reason(conn, task_id, attempts):
    """Diagnose fuer finalen BLOCKED aus dem juengsten Fehl-Job (kein stiller Verlust)."""
    r = conn.execute(
        "SELECT error_code, error_summary FROM execution_jobs WHERE task_id=? AND status IN "
        "('FAILED','TIMED_OUT') ORDER BY rowid DESC LIMIT 1", (task_id,)).fetchone()
    detail = ""
    if r:
        detail = ": %s: %s" % (r["error_code"] or "?", r["error_summary"] or "kein Detail")
    return ("max_attempts_reached (%d Versuche erschoepft)%s" % (attempts, detail))[:500]


def _active_jobs_for_principal(conn, principal_id):
    return conn.execute(
        "SELECT COUNT(*) c FROM execution_jobs WHERE agent_principal_id=? AND status IN "
        "('QUEUED','STARTING','RUNNING')", (int(principal_id),)).fetchone()["c"]


def _set_job(conn, job_id, **fields):
    if not fields:
        return
    cols = ", ".join("%s=?" % k for k in fields)
    conn.execute("UPDATE execution_jobs SET %s WHERE job_id=?" % cols,
                 list(fields.values()) + [job_id])


# ---------------------------------------------------------------- Agent-Auswahl
def _worker_can_handle(registry, worker_type, task):
    """Routing-Guard (O8): Tasks mit produktiver Action-Klasse (CODE_CHANGE/DEPLOY/
    INFRASTRUCTURE) duerfen NUR an einen code-change-faehigen Worker gehen. Alle anderen
    Action-Klassen kann jeder verfuegbare Worker uebernehmen.

    Zusatz (Aktivierung CODE_CHANGE-Worker): DEPLOY/INFRASTRUCTURE werden NIE autonom
    ausgefuehrt -- kein Worker uebernimmt sie, der Task bleibt READY und wartet auf einen
    menschlichen/manuellen Pfad (Governance-Floor ist ohnehin APPROVAL)."""
    ac = (task.get("action_class") or "").upper()
    if ac in m.APPROVAL_FORCED_ACTION_CLASSES:      # DEPLOY / INFRASTRUCTURE
        return False
    if ac not in m.CODE_CHANGE_ACTION_CLASSES:
        return True
    w = registry.get(worker_type)
    return bool(w) and bool(getattr(w, "can_code_change", False))


def select_agent(conn, task, agents_list, registry):
    """Deterministisch: preferred_agent (falls verfuegbar+berechtigt), sonst erster
    passender nach agent_name. Filter: enabled, Worker verfuegbar, Principal aktiv,
    Space-ACL (claim), required_capabilities, freie Concurrency."""
    space = _space_key(conn, task["space_id"])
    need = task.get("required_capabilities") or []
    eligible = []
    for a in agents_list:
        if not a["enabled"] or not a["principal_active"]:
            continue
        if not wk.worker_available(registry, a["worker_type"]):
            continue
        if not _worker_can_handle(registry, a["worker_type"], task):
            continue                    # z. B. CODE_CHANGE nie an read-only Worker
        p_id = a["principal_id"]
        if not cap.check(conn, p_id, cap.TASK_CLAIM, space):
            continue
        if any(not cap.check(conn, p_id, c, space) for c in need):
            continue
        if _active_jobs_for_principal(conn, p_id) >= a["max_concurrency"]:
            continue
        eligible.append(a)
    if not eligible:
        return None
    pref = task.get("preferred_agent")
    if pref:
        for a in eligible:
            if str(a["principal_id"]) == str(pref):
                return a
        # preferred nicht verfuegbar -> sauberer Fallback auf andere berechtigte Agenten
    eligible.sort(key=lambda a: a["agent_name"])
    return eligible[0]


def _space_key(conn, space_id):
    r = acl.get_space_row(conn, space_id)
    return r["key"] if r else None


# ---------------------------------------------------------------- Dispatch
def claim_and_create_job(conn, task, agent, lease_seconds=DEFAULT_LEASE):
    """Atomar: Task claimen + Execution-Job anlegen. Bei Race (Claim verloren ODER
    aktiver Job existiert) -> None (Claim wird ggf. sauber freigegeben)."""
    try:
        cl = tasks.claim_task(conn, agent["principal_id"], task["task_id"],
                              lease_seconds=lease_seconds)
    except ClaimConflict:
        return None
    job_id = uuid.uuid4().hex
    attempt = _attempts(conn, task["task_id"]) + 1
    now = now_iso()
    try:
        conn.execute(
            "INSERT INTO execution_jobs(job_id, task_id, agent_principal_id, worker_type, "
            "status, created_at, lease_until, attempt, max_attempts, dispatch_token, "
            "created_by) VALUES(?,?,?,?,'QUEUED',?,?,?,3,?,?)",
            (job_id, task["task_id"], int(agent["principal_id"]), agent["worker_type"],
             now, cl["lease_until"], attempt, cl["claim_token"], DISPATCH_ACTOR))
        conn.commit()
    except sqlite3.IntegrityError:
        # bereits ein aktiver Job fuer diesen Task -> eigenen Claim zuruecknehmen
        try:
            tasks.release_task(conn, agent["principal_id"], task["task_id"], cl["claim_token"])
        except Exception:
            pass
        return None
    audit.log(conn, DISPATCH_ACTOR, "job_created", "job", job_id, task["space_id"],
              {"task": task["task_id"], "agent": agent["agent_name"], "attempt": attempt})
    agents.touch(conn, agent["agent_name"], status="busy")
    conn.commit()
    return _job_row(conn, job_id)


def execute_job(conn, job, registry, lease_seconds=DEFAULT_LEASE):
    """Fuehrt einen Job synchron aus (O2 Mock). Erfolg -> complete_task (O1 entscheidet
    COMPLETED/AWAITING_REVIEW/AWAITING_APPROVAL). Fehler -> Job FAILED + Recovery."""
    job = _job_row(conn, job["job_id"]) if isinstance(job, dict) else job
    worker = registry.get(job["worker_type"])
    _set_job(conn, job["job_id"], status="STARTING", started_at=now_iso()); conn.commit()
    if not worker or not getattr(worker, "available", False):
        return _fail_job(conn, job, "worker_unavailable", "Worker nicht verfuegbar", False)
    _set_job(conn, job["job_id"], status="RUNNING", heartbeat_at=now_iso(),
             lease_until=iso_plus(lease_seconds)); conn.commit()
    task = tasks.get_task(conn, job["task_id"])
    try:
        res = worker.run(task, job)
    except wk.WorkerError as e:
        return _fail_job(conn, job, e.code, str(e)[:200], e.retryable)
    except wk.WorkerUnavailable as e:
        return _fail_job(conn, job, "worker_unavailable", str(e)[:200], False)
    except Exception as e:                       # noqa: BLE001 (kein Traceback nach aussen)
        return _fail_job(conn, job, "worker_error", str(e)[:200], True)
    # Erfolg: Lease erneuern + Task ueber O1 abschliessen (Gate entscheidet)
    try:
        tasks.renew_claim(conn, job["agent_principal_id"], job["task_id"],
                          job["dispatch_token"], lease_seconds=lease_seconds)
        # Task.result traegt das VOLLSTAENDIGE Worker-Ergebnis (bis ~2 KB), nicht nur
        # die Kurz-Summary: strukturierte Consumer (z. B. ein Bot, der ANALYST-JSON erwartet) muessen
        # das ganze Resultat validieren koennen. Grosse Rohlogs bleiben Sache spaeterer
        # Artifact-Refs; die Summary dient weiter Audit/UI-Kurzanzeige.
        tasks.complete_task(conn, job["agent_principal_id"], job["task_id"],
                            job["dispatch_token"],
                            result=(res.get("result") or res.get("summary")),
                            result_refs=res.get("result_refs"))
    except Exception as e:                       # noqa: BLE001
        return _fail_job(conn, job, "complete_failed", str(e)[:200], False)
    _set_job(conn, job["job_id"], status="SUCCEEDED", finished_at=now_iso(),
             heartbeat_at=now_iso(), result_ref=(res.get("result") or "")[:500])
    audit.log(conn, DISPATCH_ACTOR, "job_succeeded", "job", job["job_id"], None,
              {"task": job["task_id"]})
    _touch_agent(conn, job, "idle")
    conn.commit()
    return _job_row(conn, job["job_id"])


# Fehler, die NIEMALS automatisch retried werden (Policy).
_NON_RETRYABLE = {"permission_denied", "policy_denied", "invalid_input", "rejected",
                  "approval_denied", "worker_unavailable", "complete_failed",
                  # O3 Claude-Worker: nicht-transiente Fehler
                  "auth_failed", "token_file_missing", "token_file_insecure",
                  "mcp_forbidden", "malformed_output"}


def _fail_job(conn, job, code, summary, retryable):
    now = now_iso()
    _set_job(conn, job["job_id"], status="FAILED", finished_at=now, error_code=code,
             error_summary=summary, heartbeat_at=now)
    conn.commit()
    attempts = _attempts(conn, job["task_id"])                 # inkl. dieses FAILED
    retry = retryable and code not in _NON_RETRYABLE and attempts < job["max_attempts"]
    reason = "%s: %s" % (code, summary or "kein Detail")
    if retry:
        # Retry: Versuchszahl am Task fortschreiben (sichtbar), zurueck in die Queue.
        _reset_task(conn, job["task_id"], m.READY, retry_count=attempts)
        audit.log(conn, DISPATCH_ACTOR, "job_failed", "job", job["job_id"], None,
                  {"code": code, "retryable": 1, "attempt": attempts})
    else:
        # Endgueltig: BLOCKED NUR mit nicht-leerer Diagnose (kein stiller Verlust).
        _reset_task(conn, job["task_id"], m.BLOCKED, failure_reason=reason,
                    retry_count=attempts)
        audit.log(conn, DISPATCH_ACTOR, "job_failed", "job", job["job_id"], None,
                  {"code": code, "retryable": 0, "attempt": attempts, "gaveup": 1})
    _touch_agent(conn, job, "idle")
    conn.commit()
    return _job_row(conn, job["job_id"])


def _reset_task(conn, task_id, status, failure_reason=None, retry_count=None):
    """System-Recovery: Task-Claim sauber loesen und Status setzen (READY=Retry,
    BLOCKED=Aufgabe). Direkt (Engine-intern), damit kein Zombie-Claim bleibt.

    Diagnose-Pflicht (Fix: kein stiller BLOCKED): Ein Task wird NIE mit status=BLOCKED
    ohne nicht-leeren failure_reason geschrieben. Wird bei BLOCKED kein Grund uebergeben,
    greift ein sichtbarer Fallback statt eines stillen Verlusts. retry_count wird — wenn
    uebergeben — mitgeschrieben, damit die Zahl der Versuche am Task selbst sichtbar ist
    (nicht nur in execution_jobs)."""
    if status == m.BLOCKED and not failure_reason:
        failure_reason = "BLOCKED ohne uebergebene Diagnose (Fallback) — siehe execution_jobs"
    sets = ["status=?", "claimed_by=NULL", "claimed_at=NULL", "lease_until=NULL",
            "claim_token=NULL", "updated_at=?"]
    args = [status, now_iso()]
    if failure_reason is not None:
        sets.append("failure_reason=?"); args.append(str(failure_reason)[:500])
    if retry_count is not None:
        sets.append("retry_count=?"); args.append(int(retry_count))
    args.append(task_id)
    conn.execute("UPDATE tasks SET %s WHERE task_id=?" % ", ".join(sets), args)


def _touch_agent(conn, job, status):
    a = conn.execute("SELECT agent_name FROM agents WHERE principal_id=?",
                     (int(job["agent_principal_id"]),)).fetchone()
    if a:
        agents.touch(conn, a["agent_name"], status=status)


# ---------------------------------------------------------------- Recovery / Approval
def recover_timeouts(conn, lease_grace=0):
    """RUNNING/STARTING-Jobs mit abgelaufenem Lease -> TIMED_OUT; Task-Claim wird
    kontrolliert freigegeben (READY, retrybar) bzw. BLOCKED bei erschoepften Versuchen."""
    now = now_iso()
    rows = conn.execute(
        "SELECT * FROM execution_jobs WHERE status IN ('STARTING','RUNNING') "
        "AND lease_until IS NOT NULL AND lease_until < ?", (now,)).fetchall()
    recovered = []
    for j in rows:
        j = dict(j)
        _set_job(conn, j["job_id"], status="TIMED_OUT", finished_at=now,
                 error_code="timeout", error_summary="Lease abgelaufen (kein Heartbeat)")
        conn.commit()
        attempts = _attempts(conn, j["task_id"])
        if attempts < j["max_attempts"]:
            _reset_task(conn, j["task_id"], m.READY, retry_count=attempts)
        else:
            _reset_task(conn, j["task_id"], m.BLOCKED, retry_count=attempts,
                        failure_reason="timeout: Lease abgelaufen (kein Heartbeat) nach "
                                       "%d Versuchen" % attempts)
        audit.log(conn, DISPATCH_ACTOR, "job_timed_out", "job", j["job_id"], None,
                  {"task": j["task_id"], "attempt": attempts})
        conn.commit()
        recovered.append(j["job_id"])
    return recovered


def promote_approved(conn):
    """APPROVED-Tasks (Gate offen) fuer die Nach-Approval-Ausfuehrung wieder runnable
    machen -> READY. Erst NACH Approval; rejected Tasks bleiben unberuehrt."""
    rows = conn.execute("SELECT * FROM tasks WHERE status='APPROVED' AND approved_at "
                        "IS NOT NULL").fetchall()
    promoted = []
    for t in rows:
        t = dict(t)
        if _has_active_job(conn, t["task_id"]):
            continue
        conn.execute("UPDATE tasks SET status='READY', updated_at=? WHERE task_id=?",
                     (now_iso(), t["task_id"]))
        audit.log(conn, DISPATCH_ACTOR, "task_post_approval_ready", "task", t["task_id"],
                  t["space_id"], {})
        promoted.append(t["task_id"])
    conn.commit()
    return promoted


# ---------------------------------------------------------------- Ops-Guardrails (O5)
def _meminfo_mb():
    """(MemAvailable, SwapUsed) in MB aus /proc/meminfo. Pure stdlib, kein subprocess."""
    vals = {}
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                k, _, rest = line.partition(":")
                vals[k] = int(rest.split()[0]) // 1024   # kB -> MB
    except Exception:
        return None, None
    avail = vals.get("MemAvailable")
    swap_used = None
    if "SwapTotal" in vals and "SwapFree" in vals:
        swap_used = vals["SwapTotal"] - vals["SwapFree"]
    return avail, swap_used


def free_mb():
    return _meminfo_mb()[0]


def _consecutive_failures(conn, n):
    """True, wenn die letzten n Execution-Jobs ALLE fehlgeschlagen sind (Circuit-Breaker)."""
    if n <= 0:
        return False
    # rowid = monotone Einfuege-Reihenfolge (robuster als sekundengenaues created_at).
    rows = conn.execute("SELECT status FROM execution_jobs ORDER BY rowid DESC LIMIT ?",
                        (n,)).fetchall()
    return len(rows) == n and all(r["status"] in FAILED_JOB for r in rows)


# ---------------------------------------------------------------- Tick / Loop
def dispatch_tick(conn, registry=None, lease_seconds=DEFAULT_LEASE,
                  free_mb_override=None, min_free_mb=None, max_consec_fails=None):
    """Ein Dispatch-Zyklus. Immer: Timeout-Recovery (Safety). Nur wenn NICHT pausiert:
    Ops-Guardrails (Circuit-Breaker + RAM-Floor) -> Approval-Promotion -> neue Dispatches.

    Guardrails (O5, konservativ, 4 GB RAM):
    - Circuit-Breaker: N aufeinanderfolgende Fehl-Jobs -> sticky Auto-Pause (manuelles Resume).
    - RAM-Floor: bei zu wenig freiem RAM diesen Tick NICHT dispatchen (soft, self-healing)."""
    registry = registry or wk.build_default_registry()
    out = {"recovered": recover_timeouts(conn), "dispatched": [], "paused": False,
           "auto_paused": False, "low_memory": False}
    if not settings.dispatcher_enabled(conn):
        out["paused"] = True
        return out
    # Circuit-Breaker (sticky): systemischer Fehler -> global pausieren.
    k = config.DISPATCH_MAX_CONSEC_FAILS if max_consec_fails is None else max_consec_fails
    if _consecutive_failures(conn, k):
        settings.set_dispatcher_enabled(conn, DISPATCH_ACTOR, False)
        settings.set_autonomy_hold(conn, DISPATCH_ACTOR, True)   # Fault haelt das Fenster zu
        audit.log(conn, DISPATCH_ACTOR, "dispatcher_auto_paused", "dispatcher", "global",
                  None, {"reason": "consecutive_failures", "threshold": k}, commit=True)
        out["auto_paused"] = True
        out["paused"] = True
        return out
    # RAM-Floor (soft): keinen neuen Claude-Job starten, wenn RAM knapp ist.
    floor = config.DISPATCH_MIN_FREE_MB if min_free_mb is None else min_free_mb
    fm = free_mb() if free_mb_override is None else free_mb_override
    if floor and fm is not None and fm < floor:
        out["low_memory"] = True
        print("dispatch skipped: low memory (%s MB < %s MB floor)" % (fm, floor), flush=True)
        return out
    promote_approved(conn)
    agents_list = agents.list_agents(conn)
    for t in tasks.list_tasks(conn, status=m.READY, limit=500):
        if _has_active_job(conn, t["task_id"]):
            continue
        if tasks.deps_state(conn, t) != "satisfied":
            continue
        att = _attempts(conn, t["task_id"])
        if att >= 3:
            _reset_task(conn, t["task_id"], m.BLOCKED, retry_count=att,
                        failure_reason=_last_failure_reason(conn, t["task_id"], att))
            audit.log(conn, DISPATCH_ACTOR, "dispatch_giveup", "task", t["task_id"],
                      t["space_id"], {"attempts": att})
            conn.commit()
            continue
        agent = select_agent(conn, t, agents_list, registry)
        if not agent:
            continue
        job = claim_and_create_job(conn, t, agent, lease_seconds=lease_seconds)
        if not job:
            continue
        execute_job(conn, job, registry, lease_seconds=lease_seconds)
        out["dispatched"].append(job["job_id"])
    return out


# ---------------------------------------------------------------- Controls (ADMIN)
def _require_admin(conn, actor):
    if not acl.is_admin(conn, pid(actor)):
        raise PermissionDenied("nur ADMIN darf den Dispatcher steuern")


def pause_dispatcher(conn, actor):
    _require_admin(conn, actor)
    settings.set_dispatcher_enabled(conn, actor, False)
    audit.log(conn, actor, "dispatcher_paused", "dispatcher", "global", None, {}, commit=True)
    return {"dispatcher_enabled": False}


def resume_dispatcher(conn, actor):
    _require_admin(conn, actor)
    settings.set_dispatcher_enabled(conn, actor, True)
    settings.set_autonomy_hold(conn, actor, False)   # explizites Resume quittiert Fault/Hold
    audit.log(conn, actor, "dispatcher_resumed", "dispatcher", "global", None, {}, commit=True)
    return {"dispatcher_enabled": True}


def status(conn):
    avail, swap_used = _meminfo_mb()
    return {
        "dispatcher_enabled": settings.dispatcher_enabled(conn),
        "runnable_ready": len(tasks.list_tasks(conn, status=m.READY, limit=1000)),
        "active_jobs": conn.execute("SELECT COUNT(*) c FROM execution_jobs WHERE status IN "
                                    "('QUEUED','STARTING','RUNNING')").fetchone()["c"],
        "failed_jobs": conn.execute("SELECT COUNT(*) c FROM execution_jobs WHERE status IN "
                                    "('FAILED','TIMED_OUT')").fetchone()["c"],
        "enabled_agents": conn.execute("SELECT COUNT(*) c FROM agents WHERE enabled=1")
        .fetchone()["c"],
        "free_mb": avail, "swap_used_mb": swap_used,
        "min_free_mb": config.DISPATCH_MIN_FREE_MB,
    }


# ---------------------------------------------------------------- CLI-Loop
def run_loop(poll=DEFAULT_POLL):
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from . import config, db
    registry = wk.build_default_registry()
    print("brainy dispatcher gestartet (poll=%ss, default paused via DB-Setting)" % poll,
          flush=True)
    while True:
        try:
            conn = db.connect(config.DB_PATH)
            try:
                res = dispatch_tick(conn, registry=registry)
                if res["dispatched"] or res["recovered"]:
                    print("tick: dispatched=%d recovered=%d paused=%s"
                          % (len(res["dispatched"]), len(res["recovered"]), res["paused"]),
                          flush=True)
            finally:
                conn.close()
        except Exception as e:                   # noqa: BLE001 — Loop bleibt am Leben
            print("dispatch error: %s" % str(e)[:200], flush=True)
        time.sleep(poll)


if __name__ == "__main__":
    run_loop()
