"""Brainy MCP over stdio (newline-delimited JSON-RPC), for local MCP clients such as
Claude Desktop or for MCP inspectors.

Every message is handled by the same core as the HTTP endpoint (BrainyService.handle_mcp),
so authentication, ACL, scopes, rate limits and audit apply unchanged.

Normal mode (your real installation):
    BRAINY_DB_PATH=... BRAINY_KNOWLEDGE_ROOT=... BRAINY_TOKEN=<service token> \\
        python3 scripts/stdio.py

Demo mode (throwaway database + example knowledge in a temp dir, nothing is kept):
    python3 scripts/stdio.py --demo

Only JSON-RPC goes to stdout; all logging goes to stderr.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from brainy import auth, config, db, service, spaces  # noqa: E402


def _log(msg):
    print("brainy-stdio: %s" % msg, file=sys.stderr, flush=True)


def _setup_demo():
    tmp = tempfile.mkdtemp(prefix="brainy-demo-")
    kroot = os.path.join(tmp, "knowledge")
    shutil.copytree(os.path.join(ROOT, "examples", "knowledge"), kroot)
    git = ["git", "-C", kroot, "-c", "user.name=brainy", "-c", "user.email=brainy@localhost"]
    for args in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "demo knowledge"]):
        subprocess.run(git + args, check=True, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    db_path = os.path.join(tmp, "brainy.db")
    conn = db.init_db(db_path)
    res = auth.bootstrap_admin(conn, name="demo-admin", with_token=True)
    spaces.seed_defaults(conn, res["principal_id"])
    conn.close()
    _log("demo mode: temporary data in %s (deleted on exit)" % tmp)
    return tmp, db_path, kroot, res["token"]


def main():
    demo = "--demo" in sys.argv[1:]
    tmp = None
    if demo:
        tmp, db_path, kroot, token = _setup_demo()
    else:
        db_path, kroot = config.DB_PATH, config.KNOWLEDGE_ROOT
        token = os.environ.get("BRAINY_TOKEN", "").strip()
        if not token:
            _log("BRAINY_TOKEN is not set (use --demo to try Brainy without a setup)")
            sys.exit(2)
    svc = service.BrainyService(db_path, kroot, rate_limit=config.RATE_LIMIT)
    bearer = "Bearer " + token
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            _status, _ctype, body = svc.handle_mcp("POST", bearer, line.encode("utf-8"))
            if body:
                sys.stdout.write(body.decode("utf-8") + "\n")
                sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
