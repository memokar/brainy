"""Harte Path-Allowlist fuer den Knowledge-Service.

Brainy darf AUSSCHLIESSLICH innerhalb von BRAINY_KNOWLEDGE_ROOT arbeiten und dort
nur die kanonischen Bereiche projects/ tools/ systems/ shared/ team/ + README.md.
team/ = gemeinsamer Bereich mit externen Mitwirkenden (eigene Space-ACL).
Verboten: absolute Fremdpfade, '..', Symlink-Escape, .git/, Backups, temp/versteckt.
"""
import os

from .errors import BrainyError

KNOWLEDGE_ROOT = os.environ.get("BRAINY_KNOWLEDGE_ROOT", "/opt/brainy-knowledge")

ALLOWED_TOP = ("projects", "tools", "systems", "shared", "team")
ALLOWED_ROOT_FILES = ("README.md",)


class PathNotAllowed(BrainyError):
    """Pfad verletzt die Allowlist (Traversal/Escape/verbotener Bereich)."""


def knowledge_root(root=None):
    return os.path.realpath(root or KNOWLEDGE_ROOT)


def _bad_component(name):
    n = name.lower()
    if name in ("", ".", ".."):
        return True
    if name == ".git":
        return True
    if name.startswith("."):          # versteckte / temporaere Dateien
        return True
    if ".bak" in n or n.endswith(".tmp") or n.endswith("~") or n.endswith(".swp"):
        return True
    return False


def normalize_rel(path):
    """Nimmt einen relativen Knowledge-Pfad entgegen und gibt ihn normalisiert
    zurueck ODER wirft PathNotAllowed. KEIN Zugriff aufs Dateisystem hier."""
    if path is None:
        raise PathNotAllowed("leerer Pfad")
    p = str(path).replace("\\", "/").strip()
    if p == "":
        raise PathNotAllowed("leerer Pfad")
    if os.path.isabs(p) or p.startswith("~"):
        raise PathNotAllowed("absolute/fremde Pfade verboten: %s" % path)
    parts = [seg for seg in p.split("/") if seg != ""]
    for seg in parts:
        if _bad_component(seg):
            raise PathNotAllowed("verbotenes Pfad-Segment: %s" % seg)
    rel = "/".join(parts)
    # erlaubte Bereiche
    if rel in ALLOWED_ROOT_FILES:
        return rel
    top = parts[0]
    if top not in ALLOWED_TOP:
        raise PathNotAllowed("Bereich nicht erlaubt: %s" % top)
    return rel


def resolve(path, root=None, require_md=True):
    """Validiert + loest den Pfad real auf (Symlink-Escape wird abgefangen).
    Gibt (rel, abs_path) zurueck. Wirft PathNotAllowed bei Verstoss."""
    rel = normalize_rel(path)
    if require_md and not rel.endswith(".md"):
        raise PathNotAllowed("nur .md-Dokumente erlaubt: %s" % rel)
    r = knowledge_root(root)
    abs_path = os.path.realpath(os.path.join(r, rel))
    # Symlink-/Traversal-Escape: aufgeloester Pfad MUSS unter root liegen
    if abs_path != r and not abs_path.startswith(r + os.sep):
        raise PathNotAllowed("Pfad verlaesst den Knowledge-Root (Symlink/Escape)")
    # Nach Aufloesung erneut Bereich pruefen (Symlink koennte in .git/ zeigen)
    rel_after = os.path.relpath(abs_path, r).replace("\\", "/")
    if rel_after != rel:
        # Re-validieren (wirft bei .git/Backup/Escape)
        normalize_rel(rel_after)
    return rel, abs_path


def space_for_path(path):
    """Logischer ACL-Space eines Dokuments = Top-Level-Kategorie (README -> shared).
    Brand-/feinere ACL kann spaeter (Phase C) darueber gelegt werden."""
    rel = normalize_rel(path)
    if rel in ALLOWED_ROOT_FILES:
        return "shared"
    return rel.split("/", 1)[0]
