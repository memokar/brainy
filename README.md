# Brainy

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

## Features

| Area | What you get |
|---|---|
| Knowledge | `list_documents`, `get_document`, `search_knowledge`, `write_document` (optimistic concurrency via Git commit), `append_document`, `propose_write` |
| Tasks | `create_task`, `claim_task`, `renew_claim`, `complete_task`, `fail_task`, `release_task`, dependencies, priorities, review/approve/reject |
| Access | Spaces (tenants/areas), roles `ADMIN` / `EDITOR` / `AGENT` / `READER`, per-space ACL, service tokens, OAuth 2.1 (for Claude/ChatGPT remote connectors) |
| Operations | Web admin UI, audit log, agent registry + dispatcher framework, backup & verified restore scripts |

## Quickstart (Docker)

```bash
git clone https://github.com/memokar/brainy.git
cd brainy
docker compose up -d
docker compose logs brainy   # prints your one-time ADMIN token on first start
```

Brainy now listens on `http://127.0.0.1:8765` (MCP endpoint: `/mcp`, admin UI: `/admin`).
For remote AI connectors put it behind HTTPS (see `deploy/nginx-brainy.conf.example`) and set
`BRAINY_PUBLIC_BASE_URL`.

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

- **Claude Code / any MCP client with headers:** point it at `https://<your-host>/mcp` with
  `Authorization: Bearer <service token>`.
- **Claude.ai / ChatGPT remote connectors:** use the OAuth 2.1 flow (discovery at
  `/.well-known/oauth-authorization-server`). Set `BRAINY_PUBLIC_BASE_URL` to your HTTPS URL.

Give each AI its own principal (e.g. `claude`, `chatgpt`) with role `AGENT` and only the spaces it
needs. Every action then shows up in the audit log under that name.

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

- The web UI, log messages and code comments are still mostly **German**; English i18n is planned.
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
