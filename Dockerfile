ARG PYTHON_IMAGE=python:3.11-slim-bookworm
FROM ghcr.io/astral-sh/uv:0.11.10 AS uv
FROM ${PYTHON_IMAGE}
COPY --from=uv /uv /uvx /usr/local/bin/
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    CHECKIN_WEB_HOST=0.0.0.0 \
    CHECKIN_WEB_PORT=8765 \
    CHECKIN_WEB_DATA_DIR=/data \
    CHECKIN_WEB_KEY_FILE=/keys/master.key \
    CHECKIN_WEB_PASSWORD_FILE=/run/secrets/web-password
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev \
    && groupadd --gid 10001 checkin \
    && useradd --uid 10001 --gid checkin --create-home --shell /usr/sbin/nologin checkin \
    && mkdir -p /data /keys \
    && chown -R checkin:checkin /data /opt/venv
COPY . .
RUN chmod 0555 /app/scripts/start_server.sh
USER checkin:checkin
EXPOSE 8765
ENTRYPOINT ["/app/scripts/start_server.sh"]
CMD ["uv", "run", "--frozen", "--no-dev", "python", "-m", "server"]
