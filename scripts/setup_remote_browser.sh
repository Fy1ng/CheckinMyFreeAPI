#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="${RUNNER_TEMP:?RUNNER_TEMP is required}/checkin-tools"
mkdir -p "$TOOLS_DIR"
VERSION='2026.9.3'
DIGEST='77e26d8d900e0b8469f416239d14b5f296525fdf79fee6f511ef55609e3fbac2'
curl --fail --silent --show-error --location --retry 3 \
  "https://github.com/cloudflare/cloudflared/releases/download/${VERSION}/cloudflared-linux-amd64" \
  --output "$TOOLS_DIR/cloudflared"
printf '%s  %s\n' "$DIGEST" "$TOOLS_DIR/cloudflared" | sha256sum --check --status
chmod 700 "$TOOLS_DIR/cloudflared"
printf '%s\n' "$TOOLS_DIR" >> "${GITHUB_PATH:?GITHUB_PATH is required}"
echo 'Verified cloudflared installed; remote access starts only when authentication requires it'
