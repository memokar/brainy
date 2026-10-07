#!/bin/sh
# First start: create the knowledge Git repo, the database and a one-time ADMIN token.
set -eu

# One-command demo, no clone, no setup: `docker run --rm -i ghcr.io/memokar/brainy:latest --demo`
# Runs the stdio MCP server against a throwaway DB + example knowledge in a temp dir
# (deleted on exit). Nothing is written to the /data volume. Default (no args) is unchanged.
if [ "${1:-}" = "--demo" ]; then
    exec python3 /app/scripts/stdio.py --demo
fi

if [ ! -d "$BRAINY_KNOWLEDGE_ROOT/.git" ]; then
    mkdir -p "$BRAINY_KNOWLEDGE_ROOT"
    cp -r /app/examples/knowledge/. "$BRAINY_KNOWLEDGE_ROOT/"
    git -C "$BRAINY_KNOWLEDGE_ROOT" init -q
    git -C "$BRAINY_KNOWLEDGE_ROOT" config user.name "brainy"
    git -C "$BRAINY_KNOWLEDGE_ROOT" config user.email "brainy@localhost"
    git -C "$BRAINY_KNOWLEDGE_ROOT" add -A
    git -C "$BRAINY_KNOWLEDGE_ROOT" commit -qm "initial knowledge"
    echo "brainy: knowledge repository initialised at $BRAINY_KNOWLEDGE_ROOT"
fi

if [ ! -f "$BRAINY_DB_PATH" ]; then
    echo "brainy: first start - creating database and ADMIN token"
    echo "brainy: >>> store the following token now, it is shown only once <<<"
    python3 /app/scripts/bootstrap.py "$BRAINY_DB_PATH" --name admin --with-token
    python3 /app/scripts/init_prod_db.py "$BRAINY_DB_PATH"
fi

exec python3 /app/scripts/serve.py
