# Brainy

[![CI](https://github.com/memokar/brainy/actions/workflows/ci.yml/badge.svg)](https://github.com/memokar/brainy/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen.svg)

**A shared brain for your AI agents — and for the humans who work with them.**

Brainy is a self-hosted knowledge and task backbone that Claude, ChatGPT and any other
[MCP](https://modelcontextprotocol.io)-capable AI connect to through **one** controlled endpoint.
Every agent reads the same knowledge, works on the same task list and leaves an audit trail —
so your AIs can hand work to each other instead of living in separate chat silos.

```
   ChatGPT ─┐                                   ┌─ Git-versioned knowledge (Markdown)
   Claude  ─┼──►  MCP endpoint  ──►  Brainy  ───┼─ Tasks with atomic claim/lease
   Your bot ┘     (OAuth / tokens)   ACL+Audit  └─ Spaces, roles, append-only audit log
                                       ▲
                          Humans: web admin UI (+ optional Telegram approvals)
```

## Why Brainy?

- **AIs that collaborate.** ChatGPT creates a task, Claude claims it, does the work and writes the
  result back; a human reviews. Coordination happens through tasks — no hidden agent-to-agent magic.
- **One source of truth.** Knowledge lives as plain Markdown in a Git repository. Every write is a
  commit, so you get history, diffs and rollback for free.
- **Safe by default.** No shell, no filesystem, no eval over MCP. Path allowlist, per-space ACLs,
  secret detection on writes, rate limits, hashed tokens and an append-only audit log.
- **No double work.** Atomic task claims with leases and claim tokens guarantee that two agents
  never process the same task at the same time.
- **Human in the loop.** Agents can *propose* knowledge changes; a human approves or rejects them
  (web UI or Telegram). Tasks can require review/approval before they count as done.
- **Zero dependencies.** Pure Python standard library + SQLite. No pip install, tiny attack surface.

## Why not just a markdown file?

A shared notes file in a Git repo is a great *knowledge* store — and Brainy keeps that part on
purpose: knowledge is plain Markdown in Git, with history, diff and rollback. The problem is
everything a bare file *doesn't* do once more than one agent touches it:

- **Two agents overwrite each other.** Nothing serializes concurrent writes to the same file.
  Brainy writes go through optimistic concurrency (`expected_git_commit`) plus a server-side write
  lock: exactly one writer commits, the others get a `Conflict` and re-read — no lost edits.
- **No task hand-off.** A file can list TODOs, but it can't stop two agents from grabbing the same
  one. Brainy tasks use an **atomic claim** (`UPDATE ... WHERE status='READY'`, one row): exactly
  one agent wins, the rest get a conflict and move on.
- **No per-area permissions.** A file is all-or-nothing. Brainy has Spaces with per-space ACLs, so
  an agent only reads/writes the areas you grant it.
- **No approval step.** Agents can *propose* changes for a human to approve (web UI or Telegram)
  instead of writing straight to the source of truth.
- **"Who changed what?" beyond `git blame`.** Every action — reads of task state, claims, writes,
  rejections — lands in an append-only audit log enforced by a DB trigger.

Both guarantees above are covered by a concurrency test
([`tests/test_concurrency.py`](tests/test_concurrency.py)): 20 threads racing on one task yield
exactly **1 winner and 19 conflicts**, and 20 threads writing the same file yield exactly **1
commit and 19 conflicts**, with the repo left clean.

## How is Brainy different?

Honest comparison with the tools people mention most. Beads is closest to Brainy's *task* side, and
Central Brain to its *knowledge* side; neither is a one-to-one match. Facts are from each project's
own docs (links below); where something isn't documented, it says so rather than guessing.

| | **Brainy** | **Beads** [^beads] | **Central Brain** [^cb] | **Shared notes file** |
|---|---|---|---|---|
| What it is | Knowledge base **+** task queue | AI-agent issue/task tracker | AI memory layer | Markdown in a repo |
| Knowledge store | Markdown in Git | — (issue tracker) | Plain files + local vector index | Markdown in Git |
| Task queue with atomic claims | ✅ | ✅ | not documented | ❌ |
| Per-area permissions (ACL) | ✅ Spaces/roles | ❌ | ❌ | ❌ |
| Append-only audit log | ✅ (DB-enforced) | partial (Git/DB history) | ❌ | `git blame` only |
| Human approval for writes | ✅ (web/Telegram) | ❌ | ❌ | ❌ |
| MCP server | ✅ | ✅ | ✅ | ❌ |
| Multi-agent concurrency control | ✅ claims + write lock | ✅ claims + concurrent writers | not documented | ❌ |
| Dependencies | none (stdlib + SQLite) | bundles Dolt (Go) | bundles embedding model | n/a |
| Self-hosted | ✅ | ✅ | ✅ (cloud optional) | ✅ |
| License | AGPL-3.0 (+ commercial) | MIT | proprietary | n/a |

[^beads]: Beads — <https://github.com/steveyegge/beads> (MIT, Go; stores issues in Dolt, a
    version-controlled SQL database; earlier versions used SQLite + JSONL).
[^cb]: Central Brain by NeuroAIgent — <https://neuroaigent.ai> (local-first AI memory, Windows +
    Apple-silicon macOS, MCP integration; pricing per the site at time of writing: $12/mo solo,
    $35/mo for 4 licenses).

## Features

| Area | What you get |
|---|---|
| Knowledge | `list_documents`, `get_document`, `search_knowledge`, `write_document` (optimistic concurrency via Git commit), `append_document`, `propose_write` |
| Tasks | `create_task`, `claim_task`, `renew_claim`, `complete_task`, `fail_task`, `release_task`, dependencies, priorities, review/approve/reject |
| Resource claims | `claim_resource`, `renew_resource`, `release_resource`, `list_resource_claims` — reserve any resource (a free-form key per space, e.g. a file path or area) with an atomic lease, same model as task claims |
| Access | Spaces (tenants/areas), roles `ADMIN` / `EDITOR` / `AGENT` / `READER`, per-space ACL, service tokens, OAuth 2.1 (for Claude/ChatGPT remote connectors) |
| Operations | Web admin UI, audit log, agent registry + dispatcher framework, backup & verified restore scripts |

## Quickstart (Docker)

Try it in **one command** — no clone, no setup. Runs a throwaway demo (temporary database + example
knowledge, deleted on exit) as an MCP stdio server:

```bash
docker run --rm -i ghcr.io/memokar/brainy:latest --demo
```

For a real install, run the server (prebuilt image, published on every release):

```bash
docker run -d --name brainy -p 127.0.0.1:8765:8765 -v brainy-data:/data ghcr.io/memokar/brainy:latest
docker logs brainy   # prints your one-time ADMIN token on first start
```

Or build it yourself with Compose:

```bash
git clone https://github.com/memokar/brainy.git
cd brainy
docker compose up -d
docker compose logs brainy   # prints your one-time ADMIN token on first start
```

Brainy now listens on `http://127.0.0.1:8765` (MCP endpoint: `/mcp`, admin UI: `/admin` — log in
with the token). For remote AI connectors put it behind HTTPS (see
`deploy/nginx-brainy.conf.example`) and set `BRAINY_PUBLIC_BASE_URL`.

## Quickstart (bare metal, Linux, Python ≥ 3.10)

```bash
export BRAINY_DB_PATH=$PWD/data/brainy.db
export BRAINY_KNOWLEDGE_ROOT=$PWD/data/knowledge
export BRAINY_WEB_SESSION_KEY=$PWD/data/web_session.key

cp -r examples/knowledge "$BRAINY_KNOWLEDGE_ROOT"
git -C "$BRAINY_KNOWLEDGE_ROOT" init -q && git -C "$BRAINY_KNOWLEDGE_ROOT" add -A \
  && git -C "$BRAINY_KNOWLEDGE_ROOT" commit -qm "initial knowledge"

python3 scripts/bootstrap.py "$BRAINY_DB_PATH" --with-token   # prints ADMIN token once
python3 scripts/init_prod_db.py "$BRAINY_DB_PATH"             # seeds default spaces
python3 scripts/serve.py
```

## Connecting an AI

- **Claude Code:**
  ```bash
  claude mcp add --transport http brainy http://127.0.0.1:8765/mcp --header "Authorization: Bearer <token>"
  ```
- **Local stdio clients (e.g. Claude Desktop):** run Brainy as a subprocess:
  ```json
  {"mcpServers": {"brainy": {"command": "python3", "args": ["/opt/brainy/scripts/stdio.py"],
    "env": {"BRAINY_DB_PATH": "/var/lib/brainy/brainy.db",
            "BRAINY_KNOWLEDGE_ROOT": "/opt/brainy-knowledge", "BRAINY_TOKEN": "<token>"}}}}
  ```
  Try it without any setup: `python3 scripts/stdio.py --demo` (temporary data, deleted on exit).
- **Any other MCP client with custom headers:** endpoint `https://<your-host>/mcp`, header
  `Authorization: Bearer <service token>`.
- **Claude.ai / ChatGPT remote connectors:** use the OAuth 2.1 flow (discovery at
  `/.well-known/oauth-authorization-server`). Set `BRAINY_PUBLIC_BASE_URL` to your HTTPS URL.

Brainy is listed in the [official MCP Registry](https://registry.modelcontextprotocol.io) as
`io.github.memokar/brainy`.

Give each AI its own principal (e.g. `claude`, `chatgpt`) with role `AGENT` and only the spaces it
needs. Every action then shows up in the audit log under that name.

## Example: two coding agents in one repo

Two agents working the same repository can step on each other's files. With **resource claims**
each one reserves the area it's about to touch — a free-form key per space — and the other backs
off until it's released or the lease expires:

```jsonc
// Agent A, before editing the auth code:
claim_resource   { "space": "shared", "resource_key": "repo:app/src/auth/**", "lease_seconds": 1800 }
// -> { "claim_token": "…", "lease_until": "…" }   A now owns that area

// Agent B, about to touch the same area:
claim_resource   { "space": "shared", "resource_key": "repo:app/src/auth/**" }
// -> Conflict: already claimed  → B picks a different area (e.g. "repo:app/src/api/**")

renew_resource   { "space": "shared", "resource_key": "repo:app/src/auth/**", "claim_token": "…" }   // A keeps working
release_resource { "space": "shared", "resource_key": "repo:app/src/auth/**", "claim_token": "…" }   // A done → free again
list_resource_claims { "space": "shared" }   // who holds what right now
```

Same guarantee as task claims — exactly one holder at a time, expired leases free up automatically
(see [`tests/test_resources.py`](tests/test_resources.py)). Resource claims reuse the task
permissions/scopes (`can_claim_tasks` / `brainy:tasks:write`), so any agent that can claim tasks can
claim resources.

## Configuration

All configuration comes from environment variables — see [`.env.example`](.env.example).
Secrets (tokens, keys) are never stored in the repository or the knowledge base.

## Extensions

The core ships a worker plugin interface and a deterministic `MockWorker`. Real workers that let
agents execute tasks autonomously (e.g. Claude Code, Codex) are separate extensions loaded via
`BRAINY_WORKER_PLUGINS`. See [docs/extensions.md](docs/extensions.md).

## Running the tests

```bash
for t in tests/test_*.py; do python3 "$t" || exit 1; done
```

## Status & roadmap

Brainy runs in production for its author. Current limitations:

- Code comments are still partly German; all user-facing text is English.
- Single-node design (SQLite). PostgreSQL only if real multi-writer load appears.

## License

Copyright (C) 2026 Mehmet Karakolcu

Brainy is dual-licensed:

- **Open source:** [GNU AGPL-3.0](LICENSE). Free for everyone, including companies — but if you
  modify Brainy and offer it to others (also as a network service), you must publish your changes
  under the AGPL.
- **Commercial license:** for companies that want to use or embed Brainy without AGPL obligations.
  See [COMMERCIAL.md](COMMERCIAL.md).

Contributions require agreeing to the [Contributor License Agreement](CLA.md).
