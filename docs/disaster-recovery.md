# Brainy — Disaster Recovery Runbook

Goal: run Brainy so that it can be **restored** after data loss or server loss.
No secret values in this document. Secrets live only under `/etc/brainy/`
(root-only `0600`) and must be backed up **separately, encrypted and offsite**.

## Data classes

| Class | Location | Backup |
|---|---|---|
| Runtime state (tasks/ACL/audit/token hashes) | SQLite `/var/lib/brainy/brainy.db` | `scripts/backup.py` → SQLite online backup API (consistent) |
| Knowledge (Markdown) | Git `/opt/brainy-knowledge` | `scripts/backup.py` → `git bundle --all` (full history) |
| Secrets/config | `/etc/brainy/`, nginx vhost, systemd units, TLS | **manual, encrypted, offsite** (NOT in the backup script) |

Backup storage: `/var/backups/brainy/{daily,weekly}` (`0700`, artifacts `0600`).
Retention: **7 daily + 4 weekly** per data class. Timer: `brainy-backup.timer` (daily).

> **Important:** A local git repo/backup alone is **not** disaster recovery.
> The **external/encrypted offsite target** still needs to be configured (post-core).
> Until then: regularly pull the `daily` artifacts + `/etc/brainy` offsite, encrypted.

## Trigger / verify a backup manually

```bash
systemctl start brainy-backup.service      # one-off run
journalctl -u brainy-backup.service -n 20  # logs (no secrets)
python3 /opt/brainy/scripts/backup.py verify /var/backups/brainy/daily/brainy-<TS>.db
```

## Scenarios

### A. Entire server lost (rebuild)
1. **Install the code**: check out `/opt/brainy` from Git (repo/bundle).
2. **System user/paths/permissions**: `/var/lib/brainy` (`0700`), `/var/backups/brainy` (`0700`), Python 3 available.
3. **Restore knowledge**: latest `knowledge-*.bundle` →
   `git clone knowledge-<TS>.bundle /opt/brainy-knowledge` (then `git fsck`).
4. **Restore SQLite**: copy the latest `brainy-*.db` to `/var/lib/brainy/brainy.db`,
   `chmod 600`, `PRAGMA integrity_check` (`backup.py verify`).
5. **Secrets, manually**, from the encrypted offsite copy to `/etc/brainy/` (`0600`):
   `web_session.key`, `claude_service_token`, `admin_browser_token` (+ others if any).
6. **systemd**: install `brainy.service` + `brainy-backup.{service,timer}`,
   `daemon-reload`, `enable --now`.
7. **nginx/TLS**: deploy the `brainy.example.com` vhost; certificate from offsite
   **or** re-issue via `certbot`.
8. **Health**: `curl https://brainy.example.com/health` → 200.
9. **MCP**: `POST /mcp` without auth → 401; with token → `initialize`/`tools/list`.
10. **Admin**: `/admin/` without a session → 303 login; sign in with the browser admin token.
11. **Check audit/ACL**: exactly **1 ADMIN**, Claude/ChatGPT = **AGENT**, ChatGPT
    prod tokens = **0**, audit append-only.

### B. Only `brainy.db` damaged
1. Stop the service: `systemctl stop brainy`.
2. Move the broken DB aside (do not delete it): `mv brainy.db brainy.db.broken`.
3. Restore the latest `brainy-*.db`, `chmod 600`, `backup.py verify`.
4. Start the service, run health/MCP/admin smoke tests. (Knowledge untouched.)

### C. Knowledge repo damaged
1. `git -C /opt/brainy-knowledge fsck` for diagnosis.
2. Move the repo aside; clone the latest `knowledge-*.bundle` into a new directory,
   `git fsck`, check HEAD, move it to the old path.
3. The service needs no restart (it reads on demand). Run a read/search smoke test in the admin UI.

### D. Token/secret lost
- **Session key** lost → generate a new `web_session.key` (`0600`); all admin
  sessions become invalid (re-login required).
- **Browser admin token** lost → create **one** new token for `bootstrap-admin`
  (`tokens.create_service_token`), write the plaintext only to `/etc/brainy/admin_browser_token`
  (`0600`), revoke the old token.
- **Claude/agent token** lost/compromised → **revoke** the affected token
  (`tokens.revoke_service_token`), create a new one, store it securely in the client.
- Principle: **no default password**, plaintext shown only once, never in Git/Brain/logs/audit.

### E. TLS/nginx lost
1. Redeploy the `brainy.example.com` vhost (localhost proxy 127.0.0.1:8765, HSTS).
2. Certificate from offsite **or** `certbot --nginx -d brainy.example.com`.
3. `nginx -t && systemctl reload nginx`; check health over HTTPS.

## Restore verification (regularly, without touching prod)
- SQLite: copy the backup to a temp dir → `integrity_check` → compare counts (spaces/principals/
  tasks/audit) against the running DB (read-only) → service-layer smoke test.
- Knowledge: clone the latest bundle into a temp dir → `git fsck` → HEAD == prod HEAD →
  read `systems/brainy.md`. **Never replace the production DB/knowledge while doing this.**
