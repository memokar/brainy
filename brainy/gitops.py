"""Kontrollierte Git-Operationen (nur innerhalb eines Repos). Kein Remote/Push,
kein reset --hard/force als Normaloperation. Nur die noetigen Verben fuer den
Knowledge-Service."""
import os
import subprocess

from .errors import BrainyError


class GitError(BrainyError):
    pass


def _git(root, *args, check=True):
    r = subprocess.run(["git", "-C", root, *args],
                       capture_output=True, text=True)
    if check and r.returncode != 0:
        raise GitError((r.stderr or r.stdout or "git failed").strip())
    return r.stdout


def head_commit(root):
    return _git(root, "rev-parse", "HEAD").strip()


def status_porcelain(root):
    return _git(root, "status", "--porcelain").strip()


def is_clean(root):
    return status_porcelain(root) == ""


def exists_at_head(root, rel):
    r = subprocess.run(["git", "-C", root, "cat-file", "-e", "HEAD:" + rel],
                       capture_output=True, text=True)
    return r.returncode == 0


def add_path(root, rel):
    _git(root, "add", "--", rel)


def unstage(root, rel):
    _git(root, "reset", "-q", "--", rel, check=False)


def restore_to_head(root, rel):
    """Setzt Index UND Worktree der Datei auf HEAD zurueck (Rollback).
    Existiert die Datei nicht bei HEAD, wird sie unstaged + entfernt."""
    if exists_at_head(root, rel):
        _git(root, "checkout", "HEAD", "--", rel)
    else:
        unstage(root, rel)
        p = os.path.join(root, rel)
        if os.path.exists(p):
            os.remove(p)


def commit_path(root, rel, message, author_name="brainy", author_email="brainy@localhost"):
    """Committet NUR die zuvor gestagte Ziel-Datei. Autor = actor, Committer = repo."""
    env = dict(os.environ)
    env["GIT_AUTHOR_NAME"] = str(author_name)
    env["GIT_AUTHOR_EMAIL"] = str(author_email)
    r = subprocess.run(["git", "-C", root, "commit", "-q", "-m", message, "--", rel],
                       capture_output=True, text=True, env=env)
    if r.returncode != 0:
        raise GitError((r.stderr or r.stdout or "commit failed").strip())
    return head_commit(root)


def diff_file(root, rel, cached=False):
    args = ["diff"]
    if cached:
        args.append("--cached")
    args += ["--", rel]
    return _git(root, *args)


def log_file(root, rel, limit=20):
    out = _git(root, "log", "-%d" % int(limit),
               "--pretty=%H%x1f%aI%x1f%an%x1f%s", "--", rel)
    rows = []
    for line in out.splitlines():
        if not line.strip():
            continue
        h, ts, author, msg = (line.split("\x1f") + ["", "", "", ""])[:4]
        rows.append({"commit": h, "timestamp": ts, "author": author, "message": msg})
    return rows


def diff_between(root, rel, from_commit, to_commit):
    return _git(root, "diff", from_commit, to_commit, "--", rel)
