"""stdio transport tests: scripts/stdio.py in --demo mode and without a token.
Uses only temporary data. Run: python3 tests/test_stdio.py"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "stdio.py")

_ok = [0]
_fail = [0]


def check(label, cond, msg=""):
    if cond:
        _ok[0] += 1
        print("PASS " + label)
    else:
        _fail[0] += 1
        print("FAIL " + label + (": " + msg if msg else ""))


def run(lines, args=("--demo",), env=None):
    e = dict(os.environ)
    e.pop("BRAINY_TOKEN", None)
    e.update(env or {})
    p = subprocess.run([sys.executable, SCRIPT] + list(args),
                       input="".join(json.dumps(m) + "\n" for m in lines),
                       capture_output=True, text=True, timeout=60, env=e)
    out = [json.loads(x) for x in p.stdout.splitlines() if x.strip()]
    return p.returncode, out, p.stderr


msgs = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
     "params": {"protocolVersion": "2025-06-18", "capabilities": {}}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
     "params": {"name": "search_knowledge", "arguments": {"query": "decisions"}}},
    {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
     "params": {"name": "create_task",
                "arguments": {"space": "shared", "title": "stdio task", "type": "chore",
                              "priority": "P3"}}},
    {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
     "params": {"name": "get_document", "arguments": {"path": "../etc/passwd"}}},
]
rc, out, err = run(msgs)
by_id = {m.get("id"): m for m in out}

check("A demo exits cleanly", rc == 0, err[-300:])
check("B notification produces no output line", len(out) == 5, str(len(out)))
check("C initialize returns serverInfo brainy",
      by_id.get(1, {}).get("result", {}).get("serverInfo", {}).get("name") == "brainy")
tools = [t["name"] for t in by_id.get(2, {}).get("result", {}).get("tools", [])]
check("D tools/list contains knowledge + task tools",
      {"search_knowledge", "create_task", "claim_task"} <= set(tools), str(tools))
r3 = by_id.get(3, {}).get("result", {})
check("E search finds example knowledge",
      not r3.get("isError") and "conventions.md" in r3["content"][0]["text"], str(r3)[:200])
r4 = by_id.get(4, {}).get("result", {})
check("F create_task works", not r4.get("isError") and "stdio task" in r4["content"][0]["text"],
      str(r4)[:200])
r5 = by_id.get(5, {}).get("result", {})
check("G path traversal still rejected", r5.get("isError") is True, str(r5)[:200])
check("H stdout carries only JSON-RPC (logs on stderr)", "demo mode" in err)

rc2, out2, err2 = run([msgs[0]], args=())
check("I without BRAINY_TOKEN: exit 2, no output", rc2 == 2 and not out2, "rc=%s" % rc2)

sys.path.insert(0, ROOT)
from brainy import db  # noqa: E402
_tmp = tempfile.mkdtemp(prefix="brainy-stdio-test-")
_dbp = os.path.join(_tmp, "brainy.db")
db.init_db(_dbp).close()
rc3, out3, _ = run([msgs[0]], args=(), env={"BRAINY_TOKEN": "invalid", "BRAINY_DB_PATH": _dbp,
                                             "BRAINY_KNOWLEDGE_ROOT": _tmp})
shutil.rmtree(_tmp, ignore_errors=True)
check("J invalid token -> unauthorized error",
      out3 and out3[0].get("error", {}).get("message") == "unauthorized", str(out3)[:200])

print("\nGESAMT: %d PASS, %d FAIL" % (_ok[0], _fail[0]))
sys.exit(0 if _fail[0] == 0 else 1)
