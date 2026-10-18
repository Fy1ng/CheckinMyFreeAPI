#!/bin/sh
set -eu
umask 077

if [ "$#" -eq 0 ]; then
    set -- uv run --frozen --no-dev python -m server
fi

case "${CHECKIN_WEB_XVFB:-true}" in
    true|1|yes)
        if [ -z "${DISPLAY:-}" ]; then
            exec xvfb-run --auto-servernum --server-args='-screen 0 1920x1080x24 -nolisten tcp' "$@"
        fi
        ;;
    false|0|no) ;;
    *)
        echo 'CHECKIN_WEB_XVFB must be true or false' >&2
        exit 1
        ;;
esac

exec "$@"
