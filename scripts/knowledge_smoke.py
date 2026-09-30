"""READ-ONLY Smoke gegen den produktiven Knowledge-Root (Default /opt/brainy-knowledge).
KEIN Write. Nutzt eine TEMP-Brainy-DB mit einem ADMIN (ACL-Bypass) nur zum Lesen.
Aufruf: python3 scripts/knowledge_smoke.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from brainy import acl, db, knowledge, models as m, paths  # noqa: E402


def main():
    root = paths.knowledge_root()
    print("Knowledge-Root:", root)
    conn = db.init_db(os.path.join(tempfile.mkdtemp(prefix="brainy_ks_"), "brainy.db"))
    admin = acl.create_principal(conn, "human", "smoke-admin", m.ADMIN)
    aid = admin["id"]

    docs = knowledge.list_documents(conn, aid)
    print("1) list_documents:", len(docs), "kanonische .md")
    for d in docs[:5]:
        print("   -", d["path"], "| space", d["space"], "| git", d["git_status"])

    if docs:
        one = knowledge.get_document(conn, aid, docs[0]["path"])
        print("2) get_document:", one["path"], "->", len(one["content"]), "Bytes")

    hits = knowledge.search_knowledge(conn, aid, "brainy", limit=5)
    print("3) search 'brainy':", len(hits), "Treffer",
          [h["path"] for h in hits][:5])

    st = knowledge.get_git_status(conn, aid)
    print("4) git status: HEAD", st["head"][:10], "clean", st["clean"])

    if docs:
        hist = knowledge.get_document_history(conn, aid, docs[0]["path"], limit=3)
        print("5) history", docs[0]["path"], ":", len(hist), "Commits")
        for h in hist:
            print("   ", h["commit"][:10], h["timestamp"], h["message"][:50])
    print("SMOKE (read-only) OK — kein Write ausgefuehrt")


if __name__ == "__main__":
    main()
