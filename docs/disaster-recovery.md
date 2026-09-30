# Brainy — Disaster Recovery Runbook

Ziel: Brainy nach Datenverlust/Serververlust **wiederherstellbar** betreiben.
Keine Secret-Werte in diesem Dokument. Secrets liegen nur unter `/etc/brainy/`
(root-only `0600`) und müssen **separat verschlüsselt/offsite** gesichert werden.

## Datenklassen

| Klasse | Ort | Sicherung |
|---|---|---|
| Runtime-State (Tasks/ACL/Audit/Tokens-Hashes) | SQLite `/var/lib/brainy/brainy.db` | `scripts/backup.py` → SQLite Online-Backup-API (konsistent) |
| Knowledge (Markdown) | Git `/opt/brainy-knowledge` | `scripts/backup.py` → `git bundle --all` (komplette Historie) |
| Secrets/Config | `/etc/brainy/`, nginx-vHost, systemd-Units, TLS | **manuell, verschlüsselt, offsite** (NICHT im Backup-Script) |

Backup-Ablage: `/var/backups/brainy/{daily,weekly}` (`0700`, Artefakte `0600`).
Retention: **7 daily + 4 weekly** je Datenklasse. Timer: `brainy-backup.timer` (täglich).

> **Wichtig:** Ein lokales Git-Repo/Backup allein ist **kein** Disaster-Recovery.
> Das **externe/verschlüsselte Offsite-Ziel** ist noch zu konfigurieren (Post-Core).
> Bis dahin: `daily`-Artefakte + `/etc/brainy` regelmäßig verschlüsselt offsite ziehen.

## Backup manuell auslösen / prüfen

```bash
systemctl start brainy-backup.service      # einmaliger Lauf
journalctl -u brainy-backup.service -n 20  # Logs (ohne Secrets)
python3 /opt/brainy/scripts/backup.py verify /var/backups/brainy/daily/brainy-<TS>.db
```

## Szenarien

### A. Kompletter Server verloren (Neuaufbau)
1. **Code** installieren: `/opt/brainy` aus Git (Repo/Bundle) auschecken.
2. **Systemuser/Pfade/Rechte**: `/var/lib/brainy` (`0700`), `/var/backups/brainy` (`0700`), Python 3 vorhanden.
3. **Knowledge wiederherstellen**: neuestes `knowledge-*.bundle` →
   `git clone knowledge-<TS>.bundle /opt/brainy-knowledge` (danach `git fsck`).
4. **SQLite wiederherstellen**: neuestes `brainy-*.db` nach `/var/lib/brainy/brainy.db`
   kopieren, `chmod 600`, `PRAGMA integrity_check` (`backup.py verify`).
5. **Secrets manuell** aus verschlüsseltem Offsite nach `/etc/brainy/` (`0600`):
   `web_session.key`, `claude_service_token`, `admin_browser_token` (+ ggf. weitere).
6. **systemd**: `brainy.service` + `brainy-backup.{service,timer}` installieren,
   `daemon-reload`, `enable --now`.
7. **nginx/TLS**: vHost `brainy.example.com` einspielen; Zertifikat aus Offsite
   **oder** neu via `certbot`.
8. **Health**: `curl https://brainy.example.com/health` → 200.
9. **MCP**: `POST /mcp` ohne Auth → 401; mit Token → `initialize`/`tools/list`.
10. **Admin**: `/admin/` ohne Session → 303 Login; Login mit Browser-Admin-Token.
11. **Audit/ACL prüfen**: genau **1 ADMIN**, Claude/ChatGPT = **AGENT**, ChatGPT
    Prod-Tokens = **0**, Audit append-only.

### B. Nur `brainy.db` beschädigt
1. Dienst stoppen: `systemctl stop brainy`.
2. Defekte DB beiseitelegen (nicht löschen): `mv brainy.db brainy.db.broken`.
3. Neuestes `brainy-*.db` einspielen, `chmod 600`, `backup.py verify`.
4. Dienst starten, Health/MCP/Admin-Smoke. (Knowledge unberührt.)

### C. Knowledge-Repo beschädigt
1. `git -C /opt/brainy-knowledge fsck` zur Diagnose.
2. Repo beiseitelegen; neuestes `knowledge-*.bundle` in neues Verzeichnis klonen,
   `git fsck`, HEAD prüfen, an alten Pfad verschieben.
3. Dienst braucht keinen Neustart (liest bei Bedarf). Read-/Such-Smoke im Admin.

### D. Token/Secret verloren
- **Session-Key** verloren → neuen `web_session.key` (`0600`) erzeugen; alle Admin-
  Sessions werden ungültig (Re-Login nötig).
- **Browser-Admin-Token** verloren → für `bootstrap-admin` **ein** neues Token erzeugen
  (`tokens.create_service_token`), Klartext nur nach `/etc/brainy/admin_browser_token`
  (`0600`), altes Token revoken.
- **Claude/Agent-Token** verloren/kompromittiert → betroffenes Token **revoken**
  (`tokens.revoke_service_token`), neues erzeugen, sicher im Client hinterlegen.
- Prinzip: **kein Default-Passwort**, Klartext nur einmalig, nie in Git/Brain/Logs/Audit.

### E. TLS/nginx verloren
1. vHost `brainy.example.com` neu einspielen (localhost-Proxy 127.0.0.1:8765, HSTS).
2. Zertifikat aus Offsite **oder** `certbot --nginx -d brainy.example.com`.
3. `nginx -t && systemctl reload nginx`; Health über HTTPS prüfen.

## Restore-Verifikation (regelmäßig, ohne Prod zu berühren)
- SQLite: Backup in Temp kopieren → `integrity_check` → Counts (spaces/principals/
  tasks/audit) gegen laufende DB (read-only) vergleichen → Service-Layer Smoke.
- Knowledge: neuestes Bundle in Temp klonen → `git fsck` → HEAD == Prod-HEAD →
  `systems/brainy.md` lesen. **Produktive DB/Knowledge dabei nie ersetzen.**
