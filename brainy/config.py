"""Zentrale Runtime-Konfiguration (nur aus Environment; KEINE Secrets hartcodiert)."""
import os

DB_PATH = os.environ.get("BRAINY_DB_PATH", "/var/lib/brainy/brainy.db")
KNOWLEDGE_ROOT = os.environ.get("BRAINY_KNOWLEDGE_ROOT", "/opt/brainy-knowledge")
BIND_HOST = os.environ.get("BRAINY_BIND_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("BRAINY_BIND_PORT", "8765"))
RATE_LIMIT = os.environ.get("BRAINY_RATE_LIMIT", "240/60")   # N Anfragen / Sekunden
# Fail-closed: oeffentliches Binden nur mit ausdruecklichem Opt-in (Phase F).
ALLOW_PUBLIC = os.environ.get("BRAINY_ALLOW_PUBLIC", "0") == "1"

# ---- Operations-Guardrails (konservativ, ausgelegt auf kleine VPS) ----
# Dispatcher startet keinen neuen Job, wenn weniger als X MB frei sind (soft, self-healing).
DISPATCH_MIN_FREE_MB = int(os.environ.get("BRAINY_DISPATCH_MIN_FREE_MB", "350"))
# Circuit-Breaker: bei N aufeinanderfolgenden Fehl-Jobs -> Dispatcher Auto-Pause (sticky).
DISPATCH_MAX_CONSEC_FAILS = int(os.environ.get("BRAINY_DISPATCH_MAX_CONSEC_FAILS", "6"))

# ---- Phase O6A: OAuth-2.1-Authorization-Server (MCP Remote Connector) ----
# Oeffentliche Basis-URL (Issuer + Discovery). HTTPS-only.
PUBLIC_BASE_URL = os.environ.get("BRAINY_PUBLIC_BASE_URL", "https://brainy.example.com")
OAUTH_CODE_TTL = int(os.environ.get("BRAINY_OAUTH_CODE_TTL", "300"))            # 5 min
OAUTH_ACCESS_TTL = int(os.environ.get("BRAINY_OAUTH_ACCESS_TTL", "3600"))       # 1 h
OAUTH_REFRESH_TTL = int(os.environ.get("BRAINY_OAUTH_REFRESH_TTL", str(60 * 60 * 24 * 90)))
# Principal, unter dem OAuth-Clients (z. B. ein Claude-/ChatGPT-Account) im Audit erscheinen.
OAUTH_PRINCIPAL = os.environ.get("BRAINY_OAUTH_PRINCIPAL", "claude-account")

# ---- Telegram-Freigabekanal fuer Write-Vorschlaege (KEINE Secrets hartcodiert) ----
# Bot-Token + Webhook-Secret liegen als 0600-Dateien; nur zur Laufzeit gelesen, nie im
# Brain/Audit/Log. Owner-Chat-ID ist nicht geheim (aber Env/Config-getrieben).
TELEGRAM_TOKEN_FILE = os.environ.get("BRAINY_TELEGRAM_TOKEN_FILE",
                                     "/etc/brainy/telegram_token")
TELEGRAM_BOT_TOKEN = os.environ.get("BRAINY_TELEGRAM_BOT_TOKEN", "")      # optionaler Inline-Override
TELEGRAM_OWNER_CHAT_ID = os.environ.get("BRAINY_TELEGRAM_OWNER_CHAT_ID", "")
TELEGRAM_WEBHOOK_SECRET_FILE = os.environ.get("BRAINY_TELEGRAM_WEBHOOK_SECRET_FILE",
                                              "/etc/brainy/telegram_webhook_secret")
TELEGRAM_WEBHOOK_SECRET = os.environ.get("BRAINY_TELEGRAM_WEBHOOK_SECRET", "")
# Principal, als der eine Telegram-Freigabe ausgefuehrt wird (muss can_approve haben).
TELEGRAM_APPROVER_PRINCIPAL = os.environ.get("BRAINY_TELEGRAM_APPROVER_PRINCIPAL",
                                             "bootstrap-admin")

LOCALHOST = ("127.0.0.1", "::1", "localhost")


def is_localhost(host):
    return host in LOCALHOST
