"""Verbindliche Konstanten: Task-Status, -Typen, Rollen, Capabilities, Uebergaenge.
Siehe systems/brainy.md. Bewusst leichtgewichtig (String-Konstanten statt Enums)."""

# ----- Task-Status -----
OPEN = "OPEN"
READY = "READY"
CLAIMED = "CLAIMED"
IN_PROGRESS = "IN_PROGRESS"
BLOCKED = "BLOCKED"
COMPLETED = "COMPLETED"
FAILED = "FAILED"
CANCELLED = "CANCELLED"
# Governance-Gates (Phase O1)
AWAITING_REVIEW = "AWAITING_REVIEW"
AWAITING_APPROVAL = "AWAITING_APPROVAL"
APPROVED = "APPROVED"
REJECTED = "REJECTED"

STATUSES = {OPEN, READY, CLAIMED, IN_PROGRESS, BLOCKED, COMPLETED, FAILED, CANCELLED,
            AWAITING_REVIEW, AWAITING_APPROVAL, APPROVED, REJECTED}

# Nur READY ist "frisch" claimbar; abgelaufene CLAIMED/IN_PROGRESS werden per
# Lease-Ablauf in der Claim-SQL zusaetzlich wieder claimbar (siehe tasks.claim_task).
CLAIMABLE_FRESH = {READY}
ACTIVE_CLAIM = {CLAIMED, IN_PROGRESS}
TERMINAL = {COMPLETED, CANCELLED}  # FAILED ist re-openbar (EDITOR/ADMIN -> READY)

# CLAIMED vs IN_PROGRESS:
#   CLAIMED      = exklusiv reserviert (Lease aktiv), Arbeit noch nicht bestaetigt begonnen.
#   IN_PROGRESS  = Claim-Owner hat Bearbeitung explizit begonnen (optional; via start_progress()).
# Beide sind "aktiver Claim" und gleich zu behandeln bei Lease/Complete/Fail/Release.

# Erlaubte generische Statusuebergaenge (NUR fuer set_status(); CLAIMED/COMPLETED/
# FAILED/IN_PROGRESS werden ausschliesslich ueber claim/complete/fail/start gesetzt).
VALID_TRANSITIONS = {
    OPEN: {READY, BLOCKED, CANCELLED},
    READY: {OPEN, BLOCKED, CANCELLED},
    CLAIMED: {READY, BLOCKED},           # (release/expire fuehrt zu READY, via Engine)
    IN_PROGRESS: {READY, BLOCKED},
    BLOCKED: {READY, OPEN, CANCELLED},
    COMPLETED: set(),
    FAILED: {READY},                     # Re-open
    CANCELLED: set(),
    # Governance-Gates: generisch (set_status) nur Abbruch/Blockade zulaessig;
    # accept/approve/reject laufen ueber die Engine-Funktionen (review/approve/reject).
    AWAITING_REVIEW: {CANCELLED, BLOCKED},
    AWAITING_APPROVAL: {CANCELLED, BLOCKED},
    APPROVED: {READY, CANCELLED},         # Post-Approval-Ausfuehrung ist O2 (Dispatcher)
    REJECTED: {READY, OPEN, CANCELLED},   # Nacharbeit/erneut einreihen
}

# Status, die set_status NICHT selbst setzen darf (nur ueber die Engine-Funktionen):
ENGINE_ONLY = {CLAIMED, IN_PROGRESS, COMPLETED, FAILED,
               AWAITING_REVIEW, AWAITING_APPROVAL, APPROVED, REJECTED}

# ----- Governance (Phase O1): Ausfuehrungsmodi / Risiko / Action-Klassen -----
EXEC_AUTO = "AUTO"
EXEC_REVIEW = "REVIEW"
EXEC_APPROVAL = "APPROVAL"
EXECUTION_MODES = {EXEC_AUTO, EXEC_REVIEW, EXEC_APPROVAL}
MODE_RANK = {EXEC_AUTO: 0, EXEC_REVIEW: 1, EXEC_APPROVAL: 2}
DEFAULT_EXECUTION_MODE = EXEC_REVIEW

RISK_LOW = "LOW"; RISK_MEDIUM = "MEDIUM"; RISK_HIGH = "HIGH"; RISK_CRITICAL = "CRITICAL"
RISK_LEVELS = {RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_CRITICAL}
DEFAULT_RISK = RISK_MEDIUM

ACTION_CLASSES = {"INTERNAL_READ", "INTERNAL_WRITE", "RESEARCH", "CODE_CHANGE", "DEPLOY",
                  "PUBLISH", "EXTERNAL_MESSAGE", "CREDENTIAL", "PERMISSION", "PAYMENT",
                  "DELETE", "INFRASTRUCTURE"}

# Action-Klassen, die produktiven Code-/Server-Zugriff erfordern und daher NIEMALS an
# einen read-only Analyse-Worker geroutet werden duerfen (Phase O8). Fehlt ein
# code-change-faehiger, verfuegbarer Worker, bleibt der Task READY (wartet) -- er wird
# NICHT fehlgeroutet und NICHT still geblockt.
CODE_CHANGE_ACTION_CLASSES = {"CODE_CHANGE", "DEPLOY", "INFRASTRUCTURE"}
# Untermenge davon, die IMMER das Approval-Gate erzwingt (unabhaengig vom execution_mode).
APPROVAL_FORCED_ACTION_CLASSES = {"DEPLOY", "INFRASTRUCTURE"}

# ----- Task-Typen (Vorschlag, frei erweiterbar) -----
TASK_TYPES = {"feature", "bug", "content", "image", "research", "ops", "review", "chore"}

# ----- Prioritaeten -----
PRIORITIES = {"P1", "P2", "P3", "P4"}

# ----- Principal-Typen -----
USER = "USER"
SERVICE = "SERVICE"
# (AGENT als Principal-Typ nutzt denselben String wie die Rolle AGENT — anderes Feld)
PRINCIPAL_TYPES = {USER, "AGENT", SERVICE}
_PTYPE_NORM = {"human": USER, "user": USER, "person": USER,
               "agent": "AGENT", "bot": "AGENT",
               "service": SERVICE, "svc": SERVICE}


def normalize_ptype(t):
    """Normalisiert einen principal_type auf USER|AGENT|SERVICE oder None (ungueltig)."""
    if not t:
        return USER
    key = str(t).strip().lower()
    if key in _PTYPE_NORM:
        return _PTYPE_NORM[key]
    up = str(t).strip().upper()
    return up if up in PRINCIPAL_TYPES else None


# ----- Rollen -----
ADMIN = "ADMIN"
EDITOR = "EDITOR"
AGENT = "AGENT"
READER = "READER"
ROLES = {ADMIN, EDITOR, AGENT, READER}

# ----- Capabilities (== space_acl-Spalten) -----
CAP_READ = "can_read"
CAP_WRITE = "can_write"                 # SoT/Knowledge schreiben
CAP_CREATE_TASKS = "can_create_tasks"
CAP_CLAIM = "can_claim_tasks"
CAP_COMPLETE = "can_complete_tasks"
CAP_MANAGE_SPACE = "can_manage_space"
CAP_REVIEW = "can_review"               # Review-Gate bestaetigen/ablehnen (Phase O1)
CAP_APPROVE = "can_approve"             # Approval-Gate freigeben/ablehnen (Phase O1)
ALL_CAPS = [CAP_READ, CAP_WRITE, CAP_CREATE_TASKS, CAP_CLAIM, CAP_COMPLETE,
            CAP_MANAGE_SPACE, CAP_REVIEW, CAP_APPROVE]

# Rollen-Default-Capabilities (globale Obergrenze; Space-ACL kann NUR einschraenken).
# Review/Approve sind menschliche Governance-Rechte -> NICHT fuer AGENT/READER
# (verhindert Selbstfreigabe durch ausfuehrende Agenten).
ROLE_CAPS = {
    ADMIN: set(ALL_CAPS),
    EDITOR: {CAP_READ, CAP_WRITE, CAP_CREATE_TASKS, CAP_CLAIM, CAP_COMPLETE,
             CAP_REVIEW, CAP_APPROVE},
    # AGENT darf schreiben, ABER nur wenn die Space-ACL can_write explizit gewaehrt
    # (Rolle ist Obergrenze; READER bleibt read-only). KEIN Review/Approve.
    AGENT: {CAP_READ, CAP_WRITE, CAP_CREATE_TASKS, CAP_CLAIM, CAP_COMPLETE},
    READER: {CAP_READ},
}


def role_allows(role, capability):
    return capability in ROLE_CAPS.get(role, set())
