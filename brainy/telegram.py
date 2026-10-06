"""Telegram-Freigabekanal fuer Write-Vorschlaege (dependency-frei, stdlib urllib).

Sendet Approval-Requests mit Inline-Buttons (Freigeben/Ablehnen) an die Owner-Chat-ID
und verifiziert eingehende Callback-Updates (Webhook) ueber (1) Telegram-secret_token
und (2) Owner-Chat-ID. KEIN Token/Secret in Logs/Audit. Best-effort: fehlt die
Konfiguration oder ist Telegram nicht erreichbar, bleibt der Vorschlag trotzdem in
der DB (per Web-Admin freigebbar).
"""
import difflib
import hmac
import json
import os
import urllib.request

from . import config
from . import paths

_TG_API = "https://api.telegram.org/bot%s/%s"
_MAX_MSG = 3800   # Telegram-Limit 4096; Sicherheitsabstand


def _read_secret_file(path):
    try:
        st = os.stat(path)
        # fail-closed: nicht gruppen-/welt-lesbar
        if st.st_mode & 0o077:
            return None
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except Exception:
        return None


def bot_token():
    return config.TELEGRAM_BOT_TOKEN or _read_secret_file(config.TELEGRAM_TOKEN_FILE)


def owner_chat_id():
    return config.TELEGRAM_OWNER_CHAT_ID or None


def webhook_secret():
    return config.TELEGRAM_WEBHOOK_SECRET or _read_secret_file(config.TELEGRAM_WEBHOOK_SECRET_FILE)


def enabled():
    return bool(bot_token() and owner_chat_id())


def _api(method, payload, timeout=8):
    token = bot_token()
    if not token:
        return None
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(_TG_API % (token, method), data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


def verify_webhook_secret(header_value):
    """Timing-safe Vergleich des X-Telegram-Bot-Api-Secret-Token-Headers."""
    secret = webhook_secret()
    if not secret or not header_value:
        return False
    return hmac.compare_digest(str(header_value), str(secret))


def is_owner(from_id):
    oid = owner_chat_id()
    return bool(oid) and str(from_id) == str(oid)


def _diff_preview(old, new, path, max_chars=3000):
    new_lines = (new or "").splitlines()
    if old is None:
        body = "(new document)\n" + "\n".join("+ " + ln for ln in new_lines[:80])
    else:
        d = list(difflib.unified_diff(old.splitlines(), new_lines,
                                      lineterm="", n=2))
        body = "\n".join(d[2:]) if len(d) > 2 else "(no line changes)"
    if len(body) > max_chars:
        body = body[:max_chars] + "\n… (truncated)"
    return body


def send_approval_request(proposal, root=None):
    """Sendet die Freigabe-Anfrage mit Inline-Buttons. Gibt message_id (str) oder None."""
    if not enabled():
        return None
    old = None
    try:
        _rel, abs_path = paths.resolve(proposal["path"], root=root)
        if os.path.exists(abs_path):
            with open(abs_path, "r", encoding="utf-8") as fh:
                old = fh.read()
    except Exception:
        old = None
    diff = _diff_preview(old, proposal["content"], proposal["path"])
    text = ("Brainy: approval requested\n"
            "Space:  %s\n"
            "File:   %s\n"
            "ID:     %s\n"
            "Commit: %s\n\n"
            "--- Diff preview ---\n%s"
            % (proposal["space"], proposal["path"], proposal["proposal_id"],
               proposal.get("commit_message", ""), diff))
    if len(text) > _MAX_MSG:
        text = text[:_MAX_MSG] + "\n… (truncated)"
    kb = {"inline_keyboard": [[
        {"text": "✅ Approve", "callback_data": "ap:" + proposal["proposal_id"]},
        {"text": "❌ Reject", "callback_data": "rj:" + proposal["proposal_id"]},
    ]]}
    res = _api("sendMessage", {"chat_id": owner_chat_id(), "text": text,
                               "reply_markup": kb})
    if res and res.get("ok"):
        return str(res["result"]["message_id"])
    return None


def parse_callback(update):
    """Extrahiert die relevante Info aus einem Telegram-Callback-Update oder None."""
    cq = (update or {}).get("callback_query")
    if not cq:
        return None
    data = cq.get("data") or ""
    if ":" not in data:
        return None
    action, _, proposal_id = data.partition(":")
    msg = cq.get("message") or {}
    return {
        "action": action,
        "proposal_id": proposal_id,
        "from_id": (cq.get("from") or {}).get("id"),
        "chat_id": (msg.get("chat") or {}).get("id"),
        "message_id": msg.get("message_id"),
        "callback_query_id": cq.get("id"),
    }


def answer_callback(callback_query_id, text=""):
    if not callback_query_id:
        return None
    return _api("answerCallbackQuery", {"callback_query_id": callback_query_id,
                                        "text": text[:190]})


def edit_message(chat_id, message_id, text):
    if not (chat_id and message_id):
        return None
    return _api("editMessageText", {"chat_id": chat_id, "message_id": message_id,
                                    "text": text[:_MAX_MSG]})


def set_webhook(url, secret, timeout=10):
    """Deployment-Helfer: registriert den Webhook + secret_token beim Bot."""
    return _api("setWebhook", {"url": url, "secret_token": secret,
                               "allowed_updates": ["callback_query"]}, timeout=timeout)
