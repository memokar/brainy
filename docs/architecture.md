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
- Secret detection rejects content that looks like keys or tokens.
- `propose_write` creates a pending proposal that a human approves (web UI or Telegram).

## Backup & restore

`scripts/backup.py` uses SQLite's online backup API (with integrity check) and `git bundle` for
the knowledge repository; `scripts/restore_test.py` verifies a restore without touching
production. See [disaster-recovery.md](disaster-recovery.md).
