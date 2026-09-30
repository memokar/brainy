# Security Policy

Brainy gives AI agents access to your knowledge and tasks, so security reports are taken seriously.

## Reporting a vulnerability

Please **do not** open a public issue. Use GitHub's
[private vulnerability reporting](../../security/advisories/new) or email **<CONTACT_EMAIL>**.
Include steps to reproduce, affected version and impact. You will get an answer within 7 days.

## Security model (summary)

- MCP exposes only narrow, typed functions — no shell, filesystem or eval access.
- Knowledge access is limited by a path allowlist (no traversal, no symlink escape, no `.git`).
- Writes are scanned for secrets (keys, tokens) and rejected if one is found.
- Service tokens and OAuth tokens are stored hashed only; plaintext is shown exactly once.
- Per-space ACLs on top of roles; every write, claim and denial is recorded in an append-only log.
- The server binds to localhost by default; public binding requires `BRAINY_ALLOW_PUBLIC=1`
  and should always sit behind a TLS reverse proxy.
