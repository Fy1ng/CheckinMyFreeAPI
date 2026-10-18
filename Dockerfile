FROM ghcr.io/astral-sh/uv:0.11.10 AS uv

FROM python:3.11-slim-bookworm

COPY --from=uv /uv /uvx /usr/local/bin/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    CLOAKBROWSER_AUTO_UPDATE=false \
    CHECKIN_SECURE_MODE=true \
    CHECKIN_WEB_HOST=0.0.0.0 \
    CHECKIN_WEB_PORT=8765 \
    CHECKIN_WEB_DATA_DIR=/data \
    CHECKIN_WEB_KEY_FILE=/keys/master.key \
    CHECKIN_WEB_PASSWORD_FILE=/run/secrets/web-password \
    CHECKIN_AUTH_ROOT=/tmp/checkin-auth \
    CHECKIN_HEADLESS=false \
    NOVNC_WEB_ROOT=/usr/share/novnc

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev \
    && uv run --frozen --no-dev python -m playwright install-deps chromium \
    && apt-get update \
    && apt-get install --no-install-recommends -y \
       xvfb xauth x11vnc novnc fonts-noto-cjk fonts-noto-color-emoji \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 checkin \
    && useradd --uid 10001 --gid checkin --create-home --shell /usr/sbin/nologin checkin \
    && mkdir -p /data /keys /tmp/checkin-auth \
    && chown -R checkin:checkin /data /tmp/checkin-auth /opt/venv

COPY . .
RUN chmod 0555 /app/scripts/start_server.sh

USER checkin:checkin
ENV HOME=/home/checkin
RUN uv run --frozen --no-dev python -m cloakbrowser install

EXPOSE 8765
ENTRYPOINT ["/app/scripts/start_server.sh"]
CMD ["uv", "run", "--frozen", "--no-dev", "python", "-m", "server"]
