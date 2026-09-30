FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SPIDERLY_REQUIRE_AUTH=true \
    SPIDERLY_DB_PATH=/data/spiderly.db
WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY backend backend
COPY frontend frontend
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN useradd -r -u 10001 spiderly && mkdir /data && chown spiderly /data \
    && chmod +x /usr/local/bin/docker-entrypoint.sh
VOLUME /data
WORKDIR /app/backend
# Listens on $PORT when the platform provides one (Render, Heroku-style), else 8000.
EXPOSE 8000
HEALTHCHECK CMD python -c "import os,urllib.request as u; u.urlopen('http://127.0.0.1:%s/api/status' % os.environ.get('PORT','8000'))" || exit 1
# Starts as root only so the entrypoint can fix /data ownership, then drops to the
# unprivileged 'spiderly' user (uid 10001) before uvicorn runs.
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
