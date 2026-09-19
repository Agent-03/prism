#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/prism/app"
ENV_FILE="/opt/prism/app/.env"
BIN_DIR="/opt/prism/bin"
BIN_PATH="/opt/prism/bin/prism"

echo "[1/4] Loading environment"

cd "$APP_DIR"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "[ERROR] Missing environment file: $ENV_FILE"
    exit 1
fi

set -a
source "$ENV_FILE"
set +a

if [[ -z "${PRISM_RUNTIME_CONFIG_URL:-}" ]]; then
    echo "[ERROR] PRISM_RUNTIME_CONFIG_URL is missing from $ENV_FILE"
    exit 1
fi

if [[ -z "${PRISM_RUNTIME_CONFIG_SECRET:-}" ]]; then
    echo "[ERROR] PRISM_RUNTIME_CONFIG_SECRET is missing from $ENV_FILE"
    exit 1
fi

export PRISM_RUNTIME_CONFIG_REFRESH_SECONDS="${PRISM_RUNTIME_CONFIG_REFRESH_SECONDS:-30}"

echo "      PRISM_RUNTIME_CONFIG_URL=$PRISM_RUNTIME_CONFIG_URL"
echo "      PRISM_RUNTIME_CONFIG_SECRET=[SET]"
echo "      PRISM_RUNTIME_CONFIG_REFRESH_SECONDS=$PRISM_RUNTIME_CONFIG_REFRESH_SECONDS"

echo "[2/4] Preparing binary directory"

sudo mkdir -p "$BIN_DIR"
sudo chown "$(id -u):$(id -g)" "$BIN_DIR"

echo "[3/4] Building $BIN_PATH"

go build -trimpath -o "$BIN_PATH" ./cmd/prism
chmod +x "$BIN_PATH"

echo "Build complete:"
ls -lh "$BIN_PATH"

if [[ "${1:-}" == "--build-only" ]]; then
    exit 0
fi

echo "[4/4] Starting Prism"
echo "      Binary: $BIN_PATH"
echo "      Working directory: $APP_DIR"

cd "$APP_DIR"
exec "$BIN_PATH"