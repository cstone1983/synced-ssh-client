# sshsync server: FastAPI + SQLite (WAL) in one container, one volume (/data).

FROM python:3.13-slim AS build
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
RUN pip install --no-cache-dir uv==0.11.32
WORKDIR /srv/sshsync
# Dependencies first so this layer is cached until the lock file changes.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY app ./app
RUN uv sync --frozen --no-dev --no-editable


FROM python:3.13-slim
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/srv/sshsync/.venv/bin:$PATH" \
    SSHSYNC_DB_PATH=/data/sshsync.db

RUN groupadd --system --gid 10001 sshsync \
 && useradd --system --uid 10001 --gid sshsync --home-dir /srv/sshsync --no-create-home sshsync \
 && mkdir -p /data && chown sshsync:sshsync /data

# The virtualenv holds the dependencies and the app itself (non-editable
# install), plus the `sshsync` admin command.
COPY --from=build /srv/sshsync/.venv /srv/sshsync/.venv

USER sshsync
WORKDIR /srv/sshsync
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).status == 200 else 1)"]

# One worker only: the rate limiter lives in process memory.
# uvicorn's own proxy-header handling is off; X-Forwarded-For is honoured by
# the app itself, and only from the addresses in SSHSYNC_TRUSTED_PROXIES.
# uvicorn's access log is off; the app writes its own request log.
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", \
     "--workers", "1", "--no-proxy-headers", "--no-access-log"]
