"""Kanonische Governance-/Policy-Schicht (Phase O1).

EINE Quelle der Wahrheit fuer:
- Policy-Bewertung: requested execution_mode + risk_level + action_class -> effective_mode.
- Mode-Eskalation: Brainy stuft HOCH (nie automatisch herab).
- Sichere Defaults: unbekannt/fehlend -> mindestens REVIEW, nie AUTO bei unbekanntem Risiko.

Reine Funktionen (kein DB-Zugriff) -> von tasks/service/web gleichermassen genutzt,
damit die Regeln NICHT mehrfach dupliziert werden.
"""
from . import models as m

# Action-Klasse -> minimal erforderlicher Modus ("Floor").
ACTION_FLOOR = {
    "INTERNAL_READ": m.EXEC_AUTO,
    "RESEARCH": m.EXEC_AUTO,
    "INTERNAL_WRITE": m.EXEC_REVIEW,
    "CODE_CHANGE": m.EXEC_REVIEW,
    "DEPLOY": m.EXEC_APPROVAL,
    "PUBLISH": m.EXEC_APPROVAL,
    "EXTERNAL_MESSAGE": m.EXEC_APPROVAL,
    "CREDENTIAL": m.EXEC_APPROVAL,
    "PERMISSION": m.EXEC_APPROVAL,
    "PAYMENT": m.EXEC_APPROVAL,
    "DELETE": m.EXEC_APPROVAL,
    "INFRASTRUCTURE": m.EXEC_APPROVAL,
}
# Risiko -> Floor. CRITICAL immer APPROVAL; HIGH mindestens REVIEW.
RISK_FLOOR = {
    m.RISK_LOW: m.EXEC_AUTO,
    m.RISK_MEDIUM: m.EXEC_AUTO,
    m.RISK_HIGH: m.EXEC_REVIEW,
    m.RISK_CRITICAL: m.EXEC_APPROVAL,
}
# Konservativer Floor, wenn action_class fehlt/unbekannt.
UNKNOWN_ACTION_FLOOR = m.EXEC_REVIEW


def normalize_mode(mode):
    return mode if mode in m.EXECUTION_MODES else m.DEFAULT_EXECUTION_MODE


def normalize_risk(risk):
    """Fehlend -> MEDIUM. Vorhanden aber ungueltig -> None-Marker (konservativ behandelt)."""
    if risk in (None, ""):
        return m.DEFAULT_RISK, False        # (Wert, invalid?)
    if risk in m.RISK_LEVELS:
        return risk, False
    return risk, True                        # ungueltig -> konservativ


def normalize_action(action_class):
    if action_class in (None, ""):
        return None, False
    if action_class in m.ACTION_CLASSES:
        return action_class, False
    return action_class, True                # ungueltig


def _rank(mode):
    return m.MODE_RANK.get(mode, m.MODE_RANK[m.EXEC_REVIEW])


def evaluate_policy(requested_mode, risk_level, action_class):
    """Bewertet die Policy und liefert das effektive (>= requested) Governance-Ergebnis.

    Rueckgabe-Dict: requested, effective, risk, action_class, approval_required,
    escalated (bool), rule (menschenlesbarer Grund).
    """
    requested = normalize_mode(requested_mode)
    risk, risk_invalid = normalize_risk(risk_level)
    action, action_invalid = normalize_action(action_class)

    # Floors bestimmen (sichere Defaults).
    if action is None:
        action_floor = UNKNOWN_ACTION_FLOOR
        action_reason = "no action_class -> REVIEW"
    elif action_invalid:
        action_floor = m.EXEC_REVIEW
        action_reason = "unknown action_class '%s' -> REVIEW" % action
    else:
        action_floor = ACTION_FLOOR[action]
        action_reason = "%s requires %s" % (action, action_floor)

    if risk_invalid:
        risk_floor = m.EXEC_REVIEW           # nie AUTO bei unbekanntem Risiko
        risk_reason = "unknown risk_level '%s' -> REVIEW" % risk
    else:
        risk_floor = RISK_FLOOR[risk]
        risk_reason = "%s risk requires %s" % (risk, risk_floor)

    # Effective = strengster (hoechster Rang) aus requested + Floors. NIE herabstufen.
    candidates = [("requested", requested, _rank(requested)),
                  ("action", action_floor, _rank(action_floor)),
                  ("risk", risk_floor, _rank(risk_floor))]
    top = max(candidates, key=lambda c: c[2])
    effective = top[1]

    # Grund: der(die) Faktor(en), der/die auf den effektiven Modus hochgestuft hat/haben.
    drivers = [c for c in candidates if c[2] == top[2] and c[0] != "requested"]
    if _rank(effective) > _rank(requested) and drivers:
        rule = "; ".join(action_reason if d[0] == "action" else risk_reason for d in drivers)
    elif _rank(effective) > _rank(requested):
        rule = "policy floor -> %s" % effective
    else:
        rule = "requested %s sufficient" % requested

    return {
        "requested": requested,
        "effective": effective,
        "risk": risk if not risk_invalid else m.DEFAULT_RISK,
        "action_class": action if not action_invalid else None,
        "approval_required": effective == m.EXEC_APPROVAL,
        "escalated": _rank(effective) > _rank(requested),
        "rule": rule,
    }
