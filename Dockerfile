FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 brainy

WORKDIR /app
COPY brainy/ brainy/
COPY migrations/ migrations/
COPY scripts/ scripts/
COPY examples/ examples/
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh && mkdir -p /data && chown brainy:brainy /data

USER brainy
ENV BRAINY_DB_PATH=/data/brainy.db \
    BRAINY_KNOWLEDGE_ROOT=/data/knowledge \
    BRAINY_WEB_SESSION_KEY=/data/web_session.key \
    BRAINY_BIND_HOST=0.0.0.0 \
    BRAINY_BIND_PORT=8765 \
    BRAINY_ALLOW_PUBLIC=1 \
    PYTHONUNBUFFERED=1

VOLUME ["/data"]
EXPOSE 8765
ENTRYPOINT ["/entrypoint.sh"]
