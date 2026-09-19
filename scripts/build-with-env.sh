#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${PRISM_ENV_FILE:-$ROOT/.env}"

if [[ ! -f "$ENV_FILE" ]]; then
  printf 'ERROR: Prism env file not found: %s\n' "$ENV_FILE" >&2
  exit 1
fi

# Export every assignment from the app env file for the build and the
# launched Prism process. Nothing is embedded into the Go binary.
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

missing=0
for name in PRISM_RUNTIME_CONFIG_URL PRISM_RUNTIME_CONFIG_SECRET; do
  if [[ -z "${!name:-}" ]]; then
    printf 'ERROR: %s is missing from %s\n' "$name" "$ENV_FILE" >&2
    missing=1
  fi
done

if (( missing != 0 )); then
  exit 1
fi

printf 'Loaded Prism environment from %s\n' "$ENV_FILE"
printf 'PRISM_RUNTIME_CONFIG_URL=%s\n' "$PRISM_RUNTIME_CONFIG_URL"
printf 'PRISM_RUNTIME_CONFIG_SECRET=[SET]\n'
printf 'PRISM_RUNTIME_CONFIG_REFRESH_SECONDS=%s\n' "${PRISM_RUNTIME_CONFIG_REFRESH_SECONDS:-30}"

"$ROOT/scripts/build.sh"

if [[ -n "${PRISM_BIN:-}" ]]; then
  OUTPUT="$PRISM_BIN"
elif [[ -x /opt/prism/bin/prism ]]; then
  OUTPUT="/opt/prism/bin/prism"
else
  OUTPUT="$ROOT/bin/prism"
fi

if [[ "${1:-}" == "--build-only" ]]; then
  printf 'Build complete. Binary: %s\n' "$OUTPUT"
  exit 0
fi

if [[ ! -x "$OUTPUT" ]]; then
  printf 'ERROR: built Prism binary is not executable: %s\n' "$OUTPUT" >&2
  exit 1
fi

printf 'Starting %s with runtime environment loaded...\n' "$OUTPUT"
exec "$OUTPUT" "$@"
