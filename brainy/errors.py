"""Typisierte Brainy-Fehler (fail-closed)."""


class BrainyError(Exception):
    """Basisklasse aller Brainy-Fehler."""


class NotFound(BrainyError):
    """Objekt (Space/Task/Principal) existiert nicht."""


class PermissionDenied(BrainyError):
    """ACL/Rolle erlaubt die Aktion nicht."""


class InvalidState(BrainyError):
    """Unzulaessiger Statusuebergang oder ungueltiger Zustand."""


class ClaimConflict(BrainyError):
    """Task ist nicht (mehr) claimbar bzw. bereits geclaimt."""


class StaleToken(BrainyError):
    """claim_token ist veraltet/ungueltig (kein aktueller Claim-Owner)."""


class Conflict(BrainyError):
    """Optimistic-Concurrency-/Repo-Zustands-Konflikt (veralteter expected commit
    oder fremde uncommitted Aenderungen)."""


class SecretDetected(BrainyError):
    """Secret-Guard hat einen mutmasslichen Geheimniswert im Content gefunden."""


class AuthFailed(BrainyError):
    """Authentifizierung fehlgeschlagen (unbekannt/abgelaufen/revoked/inaktiv/falsch)."""
