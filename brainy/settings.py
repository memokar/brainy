"""Globale System-Settings (u. a. Dispatcher-Kill-Switch). Keine Secrets."""
from . import audit
from .util import now_iso

DISPATCHER_ENABLED = "dispatcher_enabled"
# Sticky "Hold": Circuit-Breaker-Fault ODER manueller Stop. Hat VORRANG vor dem
# Zeitplan-Fenster -> ein offenes Fenster (08:00) oeffnet NICHT, solange Hold aktiv ist.
AUTONOMY_HOLD = "autonomy_hold"


def get_setting(conn, key, default=None):
    r = conn.execute("SELECT value FROM system_settings WHERE key=?", (key,)).fetchone()
    return r["value"] if r else default


def set_setting(conn, key, value, actor=None):
    conn.execute(
        "INSERT INTO system_settings(key, value, updated_at) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, str(value), now_iso()))
    audit.log(conn, actor, "setting_changed", "setting", key, None, {"value": str(value)})
    conn.commit()


def dispatcher_enabled(conn):
    return str(get_setting(conn, DISPATCHER_ENABLED, "false")).lower() == "true"


def set_dispatcher_enabled(conn, actor, on):
    set_setting(conn, DISPATCHER_ENABLED, "true" if on else "false", actor)


def autonomy_hold(conn):
    return str(get_setting(conn, AUTONOMY_HOLD, "false")).lower() == "true"


def set_autonomy_hold(conn, actor, on):
    set_setting(conn, AUTONOMY_HOLD, "true" if on else "false", actor)
