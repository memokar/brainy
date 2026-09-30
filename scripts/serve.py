"""Startet den Brainy-Service (localhost-only per Default). Konfiguration via Env
(config.py). Aufruf: python3 scripts/serve.py

Phase E: zusaetzlich die Web/Admin-Oberflaeche (web.BrainyWeb) unter / und /admin/.
Backend bleibt localhost-only; oeffentliche Erreichbarkeit nur ueber Reverse-Proxy/TLS.
"""
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from brainy import config, service, web  # noqa: E402

# Session-Signierschluessel (HMAC) fuer Web-Sessions. NICHT im Repo; Datei 0600.
# Kein Default-Wert im Code -> ohne Schluesseldatei wird einmalig eine erzeugt.
SESSION_KEY_PATH = os.environ.get("BRAINY_WEB_SESSION_KEY",
                                  "/etc/brainy/web_session.key")


def _load_session_secret(path):
    try:
        with open(path, "rb") as fh:
            data = fh.read().strip()
        if len(data) >= 32:
            return data
    except FileNotFoundError:
        pass
    key = secrets.token_bytes(48)
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def main():
    svc = service.BrainyService(config.DB_PATH, config.KNOWLEDGE_ROOT, config.RATE_LIMIT)
    secret = _load_session_secret(SESSION_KEY_PATH)
    admin = web.BrainyWeb(svc, secret)
    service.run_server(svc, config.BIND_HOST, config.BIND_PORT,
                       allow_public=config.ALLOW_PUBLIC, web=admin)


if __name__ == "__main__":
    main()
