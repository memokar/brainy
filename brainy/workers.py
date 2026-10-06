"""Worker-Adapter. Fest definierte Adapter — KEINE freie Shell, kein `shell=True`,
keine beliebigen Benutzercommands, keine generische Remote-Shell.

- MockWorker: deterministisch, fuer Tests/Smoke (success/transient/permanent/timeout).
- ClaudeAdapterWorker: Platzhalter (unavailable), bis ein echter Worker registriert ist.
- Echte Worker (z. B. Claude Code, Codex) kommen als Erweiterungen/Plugins dazu:
  BRAINY_WORKER_PLUGINS="modul_a,modul_b" — jedes Modul liefert `workers()` ->
  iterierbare Worker-Instanzen (siehe docs/extensions.md).

Result-Contract (worker.run -> dict): status, summary, result, result_refs,
error_code, error_summary, metadata. Grosse Rohlogs gehoeren NICHT in Tasks
(spaeter Artifact-Refs) — O2 liefert kleine strukturierte Resultate.
"""
import importlib
import os


class WorkerUnavailable(Exception):
    """Worker-Typ ist (noch) nicht startbar (z. B. fehlender Client-Adapter)."""


class WorkerError(Exception):
    def __init__(self, message, code="worker_error", retryable=False):
        super().__init__(message)
        self.code = code
        self.retryable = retryable


class Worker:
    worker_type = "BASE"
    available = False
    # Routing (O8): Nur Worker mit can_code_change=True duerfen Tasks mit produktiver
    # Action-Klasse (CODE_CHANGE/DEPLOY/INFRASTRUCTURE) ausfuehren. Default fail-closed.
    can_code_change = False

    def run(self, task, job):
        raise NotImplementedError


class MockWorker(Worker):
    """Deterministischer Test-Worker ohne externe API. Verhalten pro task_id steuerbar."""
    worker_type = "MOCK"
    available = True

    def __init__(self, can_code_change=True):
        self.behaviors = {}     # task_id -> "success" | "transient" | "permanent" | "hang"
        # Steuerbar fuer Routing-Tests (read-only Mock vs. code-change-faehiger Mock).
        self.can_code_change = can_code_change

    def run(self, task, job):
        b = self.behaviors.get(task["task_id"], "success")
        if b == "transient":
            raise WorkerError("transient start error (mock)", code="transient", retryable=True)
        if b == "permanent":
            raise WorkerError("permission denied (mock)", code="permission_denied",
                              retryable=False)
        if b == "hang":
            # Simuliert einen nicht antwortenden Worker -> Aufrufer behandelt als Timeout.
            raise WorkerError("no heartbeat (mock hang)", code="timeout", retryable=True)
        return {"status": "SUCCEEDED",
                "summary": "[MOCK] erledigt: %s" % (task.get("title") or task["task_id"]),
                "result": "[MOCK] result for task %s" % task["task_id"],
                "result_refs": [], "error_code": None, "error_summary": None,
                "metadata": {"worker": "MOCK"}}


class ClaudeAdapterWorker(Worker):
    """Produktiver Claude-Worker — derzeit NICHT verfuegbar (kein autonom startbarer
    Claude-Client/CLI/Agent-Mode auf dem Host). Bleibt bewusst als Adapter-Blocker."""
    worker_type = "CLAUDE_ADAPTER"
    available = False
    status = "WAITING_FOR_CLIENT_ADAPTER"

    def run(self, task, job):
        raise WorkerUnavailable("Claude worker adapter not available "
                                "(WAITING_FOR_CLIENT_ADAPTER)")


def _plugin_workers():
    names = [n.strip() for n in os.environ.get("BRAINY_WORKER_PLUGINS", "").split(",")
             if n.strip()]
    for name in names:
        mod = importlib.import_module(name)
        for w in mod.workers():
            yield w


def build_default_registry():
    reg = {w.worker_type: w for w in (MockWorker(), ClaudeAdapterWorker())}
    for w in _plugin_workers():
        reg[w.worker_type] = w
    return reg


def worker_available(registry, worker_type):
    w = registry.get(worker_type)
    return bool(w) and bool(getattr(w, "available", False))
