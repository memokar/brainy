"""Brainy Resource-Claim Tests (0.2.0). Temp-DB, KEIN produktiver Zugriff.
Deckt ab: atomarer Claim (20 parallel -> 1/19), Lease-Ablauf -> wieder claimbar,
fremdes/abgelaufenes Token -> StaleToken, ACL-Verweigerung, Release gibt frei,
Listen-Filter nach Lese-ACL. Aufruf: python3 tests/test_resources.py"""
import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from brainy import acl, db, models as m, resources, spaces  # noqa: E402
from brainy.errors import ClaimConflict, NotFound, PermissionDenied, StaleToken  # noqa: E402

_ok = [0]; _fail = [0]
N = 20


def check(label, cond, msg=""):
    if cond:
        _ok[0] += 1; print("PASS " + label)
    else:
        _fail[0] += 1; print("FAIL " + label + (": " + msg if msg else ""))


def raises(exc, fn, *a, **k):
    try:
        fn(*a, **k); return False
    except exc:
        return True
    except Exception:
        return False


# ===== Setup =====
tmp = tempfile.mkdtemp(prefix="brainy_res_"); dbp = os.path.join(tmp, "brainy.db")
conn = db.init_db(dbp)
admin = acl.create_principal(conn, "USER", "admin", m.ADMIN)
for kk in ("shared", "secret"):
    spaces.create_space(conn, admin["id"], kk, kk)
agent = acl.create_principal(conn, "AGENT", "agent", m.AGENT)
agent2 = acl.create_principal(conn, "AGENT", "agent2", m.AGENT)
reader = acl.create_principal(conn, "USER", "reader", m.READER)
# shared: agent + agent2 duerfen claimen+lesen; reader nur lesen
acl.grant_permission(conn, admin["id"], "shared", agent["id"], can_read=1, can_claim_tasks=1)
acl.grant_permission(conn, admin["id"], "shared", agent2["id"], can_read=1, can_claim_tasks=1)
acl.grant_permission(conn, admin["id"], "shared", reader["id"], can_read=1)
# secret: NUR admin (agent/reader haben keine ACL) -> Listen-Filter-Test
ID = {"admin": admin["id"], "agent": agent["id"], "agent2": agent2["id"], "reader": reader["id"]}
conn.close()


def c():
    return db.connect(dbp)


# ===== 1. Claim + Felder + Listen =====
cc = c()
r = resources.claim_resource(cc, ID["agent"], "shared", "repo:app/src/auth/**", note="arbeite hier")
check("claim liefert token + lease + space", bool(r["claim_token"]) and r["lease_until"]
      and r["space"] == "shared" and r["resource_key"] == "repo:app/src/auth/**")
lst = resources.list_resource_claims(cc, ID["agent"], space="shared")
check("list zeigt den aktiven Claim mit Halter", len(lst) == 1 and lst[0]["active"]
      and lst[0]["holder"] == "agent")
TOKEN = r["claim_token"]
cc.close()

# ===== 2. Zweiter Claim auf dieselbe Ressource -> Conflict =====
cc = c()
check("zweiter Claim (anderer Agent) -> ClaimConflict",
      raises(ClaimConflict, resources.claim_resource, cc, ID["agent2"], "shared",
             "repo:app/src/auth/**"))
cc.close()

# ===== 3. Renew: Halter ok, fremdes Token -> StaleToken =====
cc = c()
rn = resources.renew_resource(cc, ID["agent"], "shared", "repo:app/src/auth/**", TOKEN,
                              lease_seconds=1200)
check("renew durch Halter verlaengert Lease", rn["lease_until"] >= r["lease_until"])
check("renew mit falschem Token -> StaleToken",
      raises(StaleToken, resources.renew_resource, cc, ID["agent"], "shared",
             "repo:app/src/auth/**", "deadbeef"))
cc.close()

# ===== 4. Release gibt frei, danach neu claimbar (auch durch anderen) =====
cc = c()
resources.release_resource(cc, ID["agent"], "shared", "repo:app/src/auth/**", TOKEN)
r2 = resources.claim_resource(cc, ID["agent2"], "shared", "repo:app/src/auth/**")
check("nach Release durch anderen Agent claimbar", r2["claim_token"] and r2["claim_token"] != TOKEN)
check("doppeltes Release (altes Token) -> StaleToken",
      raises(StaleToken, resources.release_resource, cc, ID["agent"], "shared",
             "repo:app/src/auth/**", TOKEN))
cc.close()

# ===== 5. Lease-Ablauf -> wieder claimbar; altes Token nicht mehr renewbar =====
cc = c()
rexp = resources.claim_resource(cc, ID["agent"], "shared", "deploy:staging", lease_seconds=900)
# Lease kuenstlich in die Vergangenheit setzen (Ablauf simulieren, ohne zu warten)
cc.execute("UPDATE resource_claims SET lease_until='2000-01-01T00:00:00' "
           "WHERE resource_key='deploy:staging'")
cc.commit()
r5 = resources.claim_resource(cc, ID["agent2"], "shared", "deploy:staging")
check("abgelaufener Lease -> anderer Agent kann claimen", bool(r5["claim_token"]))
check("renew auf abgelaufenem/uebernommenem Claim (altes Token) -> StaleToken",
      raises(StaleToken, resources.renew_resource, cc, ID["agent"], "shared",
             "deploy:staging", rexp["claim_token"]))
cc.close()

# ===== 6. ACL: reader (nur can_read, kein can_claim) -> PermissionDenied =====
cc = c()
check("claim ohne can_claim (reader) -> PermissionDenied",
      raises(PermissionDenied, resources.claim_resource, cc, ID["reader"], "shared", "repo:x"))
# unbekannter Space -> NotFound
check("claim in unbekanntem Space -> NotFound",
      raises(NotFound, resources.claim_resource, cc, ID["agent"], "does-not-exist", "repo:x"))
cc.close()

# ===== 7. Listen-Filter nach Lese-ACL (secret-Space nur fuer admin sichtbar) =====
cc = c()
resources.claim_resource(cc, ID["admin"], "secret", "secret:thing")
all_admin = resources.list_resource_claims(cc, ID["admin"])     # ohne space -> alle lesbaren
keys_admin = {x["resource_key"] for x in all_admin}
all_agent = resources.list_resource_claims(cc, ID["agent"])
keys_agent = {x["resource_key"] for x in all_agent}
check("admin sieht secret-Space-Claim", "secret:thing" in keys_admin)
check("agent (keine ACL auf secret) sieht secret-Claim NICHT", "secret:thing" not in keys_agent)
check("agent ohne Leserecht auf secret -> list(space=secret) PermissionDenied",
      raises(PermissionDenied, resources.list_resource_claims, cc, ID["agent"], "secret"))
cc.close()

# ===== 8. Nebenlaeufigkeit: 20 parallele Claimer -> genau 1 Gewinner, 19 Conflicts =====
barrier = threading.Barrier(N)
res = []; lock = threading.Lock()


def claim_worker(_i):
    barrier.wait()
    cx = c()
    try:
        rr = resources.claim_resource(cx, ID["agent"], "shared", "race:resource")
        with lock:
            res.append(("ok", rr))
    except ClaimConflict:
        with lock:
            res.append(("conflict", None))
    except Exception as e:  # noqa: BLE001
        with lock:
            res.append(("error", repr(e)))
    finally:
        cx.close()


ts = [threading.Thread(target=claim_worker, args=(i,)) for i in range(N)]
for t in ts:
    t.start()
for t in ts:
    t.join()
wins = [r for s, r in res if s == "ok"]
conf = sum(1 for s, _ in res if s == "conflict")
errs = [mm for s, mm in res if s == "error"]
check("parallel: genau 1 Gewinner von %d" % N, len(wins) == 1, "wins=%d" % len(wins))
check("parallel: %d Conflicts" % (N - 1), conf == N - 1, "conflicts=%d" % conf)
check("parallel: keine unerwarteten Fehler", not errs, "errors=%s" % errs[:2])

print("\nGESAMT: %d PASS, %d FAIL" % (_ok[0], _fail[0]))
sys.exit(0 if _fail[0] == 0 else 1)
