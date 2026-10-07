# Architecture

Three pillars:

- **Knowledge** — canonical Markdown documents in a Git repository (history, diff, rollback).
- **Access** — one controlled MCP endpoint for all agents; a web UI for humans.
- **Tasks** — coordination between humans and agents: who does what, status, result.

Agents never talk to each other directly. They coordinate through tasks and shared knowledge,
which keeps every interaction visible, permissioned and audited.

## Components

| Component | Role | Storage |
|---|---|---|
| Knowledge | Documents in `projects/`, `tools/`, `systems/`, `shared/`, `team/` | Markdown + Git |
| Tasks | Task engine with atomic claim/lease | SQLite (WAL) |
| Spaces | Logical areas / tenants | SQLite |
| ACL | Roles × per-space capabilities | SQLite |
| Audit | Append-only event log (enforced by DB trigger) | SQLite |
| MCP | JSON-RPC endpoint `/mcp`, OAuth 2.1 + service tokens | HTTP |
| Web | Admin UI (`/admin`) | HTTP |

## Task lifecycle

`OPEN → READY → CLAIMED → IN_PROGRESS → COMPLETED`, plus `BLOCKED`, `FAILED`, `CANCELLED`.
Only `READY` tasks can be claimed. Tasks can depend on other tasks and can require review or
approval before completion.

## Claim / lease

- A claim is a single atomic `UPDATE ... WHERE status='READY' AND (unclaimed OR lease expired)`;
  it succeeds only if exactly one row changed — two agents can never claim the same task.
- Each claim gets a new `claim_token` and a `lease_until` (default 15 min, renewable).
- `complete_task` / `fail_task` require the current token and are idempotent. After a lease
  expires and someone else claims the task, the old token is invalid.

## Roles

| Capability | READER | AGENT | EDITOR | ADMIN |
|---|:-:|:-:|:-:|:-:|
| Read knowledge / tasks | ✅ | ✅ | ✅ | ✅ |
| Write knowledge | — | — (propose) | ✅ | ✅ |
| Create / claim / complete tasks | — | ✅ | ✅ | ✅ |
| Manage spaces, principals, tokens | — | — | — | ✅ |

Effective rights = role ∩ space ACL.

## Knowledge writes

- Path allowlist: only the five areas + `README.md`, only `.md`; no `..`, hidden files, backups,
  `.git` or symlink escapes.
- Optimistic concurrency: writes carry `expected_git_commit`; stale writes are rejected.
- Serialized commits: the HEAD check and the commit run under a per-repo write lock
  (in-process `threading.Lock` + a POSIX `fcntl.flock` on `.git/brainy-write.lock`, so the lock
  covers both the multi-threaded server and separate processes such as stdio clients). This closes
  the TOCTOU gap between reading HEAD and committing — without it, `ThreadingHTTPServer` could run
  two writers in parallel and let both commit.
- Secret detection rejects content that looks like keys or tokens.
- `propose_write` creates a pending proposal that a human approves (web UI or Telegram).

## Concurrency guarantees (tested)

`tests/test_concurrency.py` exercises both races with 20 threads (each its own DB connection,
released together on a barrier):

- **Task claims:** 20 agents claim the same task → exactly **1 winner, 19 `ClaimConflict`**
  (single atomic `UPDATE ... WHERE status='READY'`).
- **Knowledge writes:** 20 agents write the same file with the same `expected_git_commit` → exactly
  **1 commit, 19 `Conflict`**; the Git history gains exactly one commit and the repo stays clean.
- **Independent writes:** 20 agents writing *different* files all succeed — the lock serializes
  commits without false conflicts or deadlock.

## Resource claims

Beyond tasks, agents can reserve **arbitrary resources** — a free-form string key per space (e.g.
`repo:app/src/auth/**`, `deploy:staging`) — so two agents don't touch the same files/area at once.

- Table `resource_claims` holds exactly one row per `(space_id, resource_key)` (UNIQUE). A claim is
  free again when `released_at IS NOT NULL` **or** `lease_until` is in the past.
- Atomic claim: `INSERT OR IGNORE` the row, else `UPDATE … WHERE released_at IS NOT NULL OR
  lease_until < now`; success needs exactly one changed row — same single-winner guarantee as task
  claims (`tests/test_resources.py`: 20 parallel claimers → 1 winner, 19 conflicts).
- `renew_resource` / `release_resource` require the current holder's `claim_token` (else
  `StaleToken`); an expired lease can be taken over by anyone.
- Permissions **reuse** the task capability/scopes: `can_claim_tasks` (`brainy:tasks:write`) to
  claim/renew/release, `can_read` (`brainy:tasks:read`) to list. No new capability.
- Read-only list in the web admin at `/admin/resources`.

## Backup & restore

`scripts/backup.py` uses SQLite's online backup API (with integrity check) and `git bundle` for
the knowledge repository; `scripts/restore_test.py` verifies a restore without touching
production. See [disaster-recovery.md](disaster-recovery.md).
