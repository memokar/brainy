# Extensions: workers

Brainy's core manages tasks, claims and execution jobs. *Who* actually executes a task is
pluggable: a **worker** is a small adapter that receives a claimed task and returns a result.

The core contains:

- `Worker` — base class (`worker_type`, `available`, `can_code_change`, `run(task, job)`)
- `MockWorker` — deterministic worker for tests and demos
- the **dispatcher** (`python3 -m brainy.dispatcher`) — picks `READY` tasks, selects an enabled
  agent, claims the task atomically, runs the worker and records the job. Paused by default.

## Writing a worker plugin

```python
# my_workers.py
from brainy.workers import Worker, WorkerError

class EchoWorker(Worker):
    worker_type = "ECHO"
    available = True

    def run(self, task, job):
        return {"status": "SUCCEEDED",
                "summary": "echo: %s" % task["title"],
                "result": task.get("description") or "",
                "result_refs": [], "error_code": None, "error_summary": None,
                "metadata": {"worker": "ECHO"}}

def workers():
    return [EchoWorker()]
```

Load it with `BRAINY_WORKER_PLUGINS=my_workers` and register an agent with
`worker_type="ECHO"` (admin UI or `brainy.agents.register_agent`).

## Result contract

`run()` returns a dict with `status`, `summary`, `result`, `result_refs`, `error_code`,
`error_summary`, `metadata`. Raise `WorkerError(message, code=..., retryable=...)` on failure;
retryable errors put the task back to `READY`, others mark it `FAILED`.

## Rules for workers

- No `shell=True`, no free-form commands from task text. Build explicit argument lists.
- Never write secrets into results, logs or the audit trail.
- Workers that change code (`can_code_change=True`) only receive tasks whose action class allows
  it; governance (review/approval) stays with the dispatcher.

## Planned official extensions

- **Claude Code worker** — runs `claude -p` headless with read-only Brainy tools.
- **Code-change worker** — Codex executes, Claude reviews, hardened sandbox for tests and commits.
- **Autonomy window** — time-based enabling/disabling of agents.
