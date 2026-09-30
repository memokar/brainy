"""Brainy Ops-Guardrails Tests (Phase O5): RAM-Floor (soft) + Circuit-Breaker (sticky).
Temp-DB, MockWorker. Aufruf: python3 tests/test_guards.py"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from brainy import (acl, agents, db, dispatcher as D, models as m, settings, spaces,  # noqa: E402
                    tasks, workers as wk)

_ok = [0]; _fail = [0]


def check(label, cond, msg=""):
    if cond:
        _ok[0] += 1; print("PASS " + label)
    else:
        _fail[0] += 1; print("FAIL " + label + (": " + msg if msg else ""))


def sh(root, *a):
    return subprocess.run(["git", "-C", root, *a], capture_output=True, text=True).stdout


def mini_kb():
    tmp = tempfile.mkdtemp(prefix="brainy_gkb_"); k = os.path.join(tmp, "kb"); os.makedirs(k)
    for d in ("projects", "tools", "systems", "shared"):
        os.makedirs(os.path.join(k, d))
    open(os.path.join(k, "systems", "brainy.md"), "w").write("# Brainy\n")
    sh(k, "init", "-q", "-b", "main"); sh(k, "config", "user.name", "kb")
    sh(k, "config", "user.email", "kb@localhost"); sh(k, "add", "-A"); sh(k, "commit", "-q", "-m", "i")
    return k


def setup():
    tmp = tempfile.mkdtemp(prefix="brainy_g_"); dbp = os.path.join(tmp, "brainy.db")
    conn = db.init_db(dbp)
    admin = acl.create_principal(conn, "USER", "admin", m.ADMIN)
    spaces.create_space(conn, admin["id"], "shared", "shared")
    ag = acl.create_principal(conn, "AGENT", "worker", m.AGENT)
    acl.grant_permission(conn, admin["id"], "shared", ag["id"], can_read=1,
                         can_create_tasks=1, can_claim_tasks=1, can_complete_tasks=1)
    agents.register_agent(conn, admin["id"], "mock", ag["id"], "MOCK", enabled=1, max_concurrency=1)
    settings.set_dispatcher_enabled(conn, admin["id"], True)
    conn.close()
    return dbp, admin["id"]


dbp, ADMIN = setup()
REG = wk.build_default_registry()
MOCK = REG["MOCK"]
c = db.connect(dbp)


def mk(title, mode="success"):
    return tasks.create_task(c, ADMIN, "shared", title, status=m.READY, execution_mode="AUTO",
                             action_class="INTERNAL_READ", description="FAKE:" + mode)


# _meminfo lokal plausibel
avail, swap = D._meminfo_mb()
check("_meminfo_mb liefert plausiblen Wert", isinstance(avail, int) and avail > 0)

# --- RAM-Floor (soft, self-healing) ---
t1 = mk("[G] lowmem")
r = D.dispatch_tick(c, registry=REG, free_mb_override=10, min_free_mb=350)
check("RAM-Floor: wenig RAM -> kein Dispatch (low_memory, Task bleibt READY)",
      r["low_memory"] and not r["dispatched"] and tasks.get_task(c, t1["task_id"])["status"] == "READY")
r = D.dispatch_tick(c, registry=REG, free_mb_override=5000, min_free_mb=350)
check("RAM-Floor self-healing: genug RAM -> Task wird dispatched + COMPLETED",
      not r["low_memory"] and tasks.get_task(c, t1["task_id"])["status"] == "COMPLETED")

# --- Circuit-Breaker (sticky) ---
# 2 permanent-fehlschlagende Tasks -> 2 FAILED-Jobs (non-retryable -> BLOCKED)
for i in range(2):
    t = mk("[G] fail%d" % i, mode="permanent")
    MOCK.behaviors[t["task_id"]] = "permanent"
    D.dispatch_tick(c, registry=REG, free_mb_override=5000, max_consec_fails=99)  # Breaker aus
failed = [j for j in D.list_jobs(c) if j["status"] == "FAILED"]
check("Setup: 2 FAILED-Jobs vorhanden", len(failed) >= 2)
# Breaker mit Schwelle 2 -> Auto-Pause beim naechsten Tick
t3 = mk("[G] after-fails")
r = D.dispatch_tick(c, registry=REG, free_mb_override=5000, max_consec_fails=2)
check("Circuit-Breaker: 2 aufeinanderfolgende Fehler -> Auto-Pause",
      r["auto_paused"] and not settings.dispatcher_enabled(c))
check("Circuit-Breaker: neuer Task NICHT dispatched (sticky paused)",
      tasks.get_task(c, t3["task_id"])["status"] == "READY" and not D.list_jobs(c, task_id=t3["task_id"]))
# Audit-Event vorhanden
acts = {r["action"] for r in c.execute("SELECT action FROM audit_events").fetchall()}
check("Audit: dispatcher_auto_paused geloggt", "dispatcher_auto_paused" in acts)
# manuelles Resume hebt sticky pause auf
settings.set_dispatcher_enabled(c, ADMIN, True)
r = D.dispatch_tick(c, registry=REG, free_mb_override=5000, max_consec_fails=99)
check("nach manuellem Resume: Dispatch wieder moeglich",
      tasks.get_task(c, t3["task_id"])["status"] == "COMPLETED")

# --- status() enthaelt Ressourcen-Felder (Observability) ---
st = D.status(c)
check("status() enthaelt free_mb/swap_used_mb/min_free_mb",
      "free_mb" in st and "swap_used_mb" in st and st["min_free_mb"] == __import__(
          "brainy.config", fromlist=["x"]).DISPATCH_MIN_FREE_MB)

c.close()
print("\nGESAMT: %d PASS, %d FAIL" % (_ok[0], _fail[0]))
sys.exit(0 if _fail[0] == 0 else 1)
