#!/bin/sh
set -eu
umask 077
if [ "$#" -eq 0 ]; then
    set -- uv run --frozen --no-dev python -m server
fi
exec "$@"
