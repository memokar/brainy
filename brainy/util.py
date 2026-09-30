"""Zeit-/Serialisierungs-Helfer. Alle Zeitstempel: UTC, ISO-8601, sekundengenau.
Dadurch ist der lexikografische String-Vergleich (lease_until < now) monoton."""
import datetime as _dt
import json as _json


def now_dt():
    return _dt.datetime.now(_dt.timezone.utc)


def now_iso():
    return now_dt().isoformat(timespec="seconds")


def iso_plus(seconds):
    return (now_dt() + _dt.timedelta(seconds=seconds)).isoformat(timespec="seconds")


def dumps(value):
    if value is None:
        return None
    return _json.dumps(value, ensure_ascii=False)


def loads(text, default=None):
    if not text:
        return default
    try:
        return _json.loads(text)
    except Exception:
        return default


def pid(x):
    """Extrahiert die principal_id aus einem AuthContext (Attribut principal_id)
    ODER gibt x unveraendert zurueck (int-id). Verhindert, dass ein AuthContext
    versehentlich als roher Actor/Name verwendet wird -> keine Auth ueber Namen."""
    return getattr(x, "principal_id", x)
