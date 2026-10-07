"""Brainy Concurrency Tests. Beweist die beiden Kern-Garantien unter echter
Nebenlaeufigkeit (Threads mit je eigener DB-Verbindung, Barrier-synchronisiert):

  1. Task-Claim: 20 gleichzeitige Claimer auf denselben Task -> genau 1 Gewinner,
     19 ClaimConflict (atomic UPDATE WHERE status='READY', rowcount==1).
  2. Knowledge-Write: 20 gleichzeitige write_document auf dieselbe Datei mit dem
     gleichen expected_git_commit -> genau 1 Commit, Rest Conflict (Optimistic
     Concurrency + Schreib-Lock). Repo bleibt sauber, genau 1 neuer Commit.
  3. Writes auf VERSCHIEDENE Dateien laufen alle durch (kein falscher Conflict,
     kein Deadlock).

Braucht POSIX (fcntl) fuer den prozessuebergreifenden Lock; In-Process-Threads
genuegen hier. Aufruf: python3 tests/test_concurrency.py"""
import os
import subprocess
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from brainy import acl, db, gitops, knowledge, models as m, spaces, tasks  # noqa: E402
from brainy.errors import ClaimConflict, Conflict  # noqa: E402

_ok = [0]; _fail = [0]
N = 20


def check(label, cond, msg=""):
    if cond:
        _ok[0] += 1; print("PASS " + label)
    else:
        _fail[0] += 1; print("FAIL " + label + (": " + msg if msg else ""))


def sh(root, *a):
    return subprocess.run(["git", "-C", root, *a], capture_output=True, text=True).stdout


def mini_kb():
    tmp = tempfile.mkdtemp(prefix="brainy_conckb_"); k = os.path.join(tmp, "kb"); os.makedirs(k)
    for d in ("projects", "tools", "systems", "shared"):
        os.makedirs(os.path.join(k, d))
    open(os.path.join(k, "shared", "race.md"), "w").write("# Race\n\nbase\n")
    sh(k, "init", "-q", "-b", "main"); sh(k, "config", "user.name", "kb")
    sh(k, "config", "user.email", "kb@localhost"); sh(k, "add", "-A"); sh(k, "commit", "-q", "-m", "init")
    return k


def commit_count(root):
    return int(sh(root, "rev-list", "--count", "HEAD").strip() or "0")


def run_parallel(n, worker):
    """Startet n Threads, synchronisiert sie auf eine Barrier und sammelt Ergebnisse."""
    barrier = threading.Barrier(n)
    results = []; lock = threading.Lock()

    def wrap(i):
        barrier.wait()
        try:
            r = worker(i)
            with lock:
                results.append(("ok", r))
        except ClaimConflict:
            with lock:
                results.append(("claim_conflict", None))
        except Conflict:
            with lock:
                results.append(("conflict", None))
        except Exception as e:  # noqa: BLE001 - im Test alles einfangen, um es sichtbar zu machen
            with lock:
                results.append(("error", repr(e)))

    ts = [threading.Thread(target=wrap, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return results


# ===== Setup: Temp-DB + Mini-KB, ein Agent mit Task- und Write-Rechten =====
tmp = tempfile.mkdtemp(prefix="brainy_conc_"); dbp = os.path.join(tmp, "brainy.db")
conn = db.init_db(dbp)
admin = acl.create_principal(conn, "USER", "admin", m.ADMIN)
spaces.create_space(conn, admin["id"], "shared", "shared")
agent = acl.create_principal(conn, "AGENT", "agent", m.AGENT)
acl.grant_permission(conn, admin["id"], "shared", agent["id"], can_read=1, can_write=1,
                     can_create_tasks=1, can_claim_tasks=1, can_complete_tasks=1)
AID = agent["id"]
conn.close()
KROOT = mini_kb()


# ===== 1. 20 gleichzeitige Claimer auf denselben Task =====
c0 = db.connect(dbp)
task = tasks.create_task(c0, AID, "shared", "race-task", status=m.READY,
                         execution_mode="AUTO", action_class="INTERNAL_READ")
c0.close()
TID = task["task_id"]


def claim_worker(_i):
    c = db.connect(dbp)
    try:
        return tasks.claim_task(c, AID, TID)
    finally:
        c.close()


res = run_parallel(N, claim_worker)
wins = [r for s, r in res if s == "ok"]
conflicts = sum(1 for s, _ in res if s == "claim_conflict")
errors = [m2 for s, m2 in res if s == "error"]
check("Claim: genau 1 Gewinner von %d" % N, len(wins) == 1, "wins=%d" % len(wins))
check("Claim: %d Konflikte" % (N - 1), conflicts == N - 1, "conflicts=%d" % conflicts)
check("Claim: keine unerwarteten Fehler", not errors, "errors=%s" % errors[:2])

# Der Gewinner-Token funktioniert, Task ist CLAIMED
c = db.connect(dbp)
check("Claim: Task ist CLAIMED", tasks.get_task(c, TID)["status"] == "CLAIMED")
if wins:
    done = tasks.complete_task(c, AID, TID, wins[0]["claim_token"], result="ok")
    check("Claim: Gewinner kann abschliessen (COMPLETED)", done["status"] == "COMPLETED")
c.close()


# ===== 2. 20 gleichzeitige Writes auf dieselbe Datei, gleicher expected_git_commit =====
base = gitops.head_commit(KROOT)
before = commit_count(KROOT)


def write_worker(i):
    c = db.connect(dbp)
    try:
        return knowledge.write_document(
            c, AID, "shared/race.md", "# Race\n\nwriter %d\n" % i, base,
            "concurrent write %d" % i, root=KROOT)
    finally:
        c.close()


res = run_parallel(N, write_worker)
wwins = [r for s, r in res if s == "ok"]
wconf = sum(1 for s, _ in res if s == "conflict")
werr = [m2 for s, m2 in res if s == "error"]
check("Write: genau 1 Commit von %d" % N, len(wwins) == 1, "wins=%d" % len(wwins))
check("Write: %d Conflicts" % (N - 1), wconf == N - 1, "conflicts=%d" % wconf)
check("Write: keine unerwarteten Fehler", not werr, "errors=%s" % werr[:2])
check("Write: genau 1 neuer Commit in der Historie", commit_count(KROOT) == before + 1,
      "delta=%d" % (commit_count(KROOT) - before))
check("Write: Repo bleibt sauber (keine uncommitted Reste)", gitops.is_clean(KROOT))
content = open(os.path.join(KROOT, "shared", "race.md"), encoding="utf-8").read()
candidates = {"# Race\n\nwriter %d\n" % i for i in range(N)}
check("Write: Dateiinhalt == genau einem Gewinner-Write", content in candidates,
      "content=%r" % content[:40])


# ===== 3. Writes auf VERSCHIEDENE Dateien laufen alle durch (kein falscher Conflict) =====
# Jeder Writer nutzt den jeweils aktuellen HEAD (eigene Datei), serialisiert durch den Lock.
def write_distinct(i):
    c = db.connect(dbp)
    try:
        # expected=None -> kein Optimistic-Gate; Lock serialisiert die Commits sauber.
        return knowledge.write_document(
            c, AID, "shared/f%02d.md" % i, "# F%02d\n\nx\n" % i, None,
            "distinct write %d" % i, root=KROOT)
    finally:
        c.close()


before2 = commit_count(KROOT)
res = run_parallel(N, write_distinct)
dwins = sum(1 for s, _ in res if s == "ok")
derr = [m2 for s, m2 in res if s == "error"]
check("Distinct-Writes: alle %d erfolgreich (kein falscher Conflict)" % N, dwins == N,
      "ok=%d" % dwins)
check("Distinct-Writes: kein Fehler/Deadlock", not derr, "errors=%s" % derr[:2])
check("Distinct-Writes: genau %d neue Commits" % N, commit_count(KROOT) == before2 + N,
      "delta=%d" % (commit_count(KROOT) - before2))
check("Distinct-Writes: Repo sauber", gitops.is_clean(KROOT))


print("\nGESAMT: %d PASS, %d FAIL" % (_ok[0], _fail[0]))
sys.exit(0 if _fail[0] == 0 else 1)
