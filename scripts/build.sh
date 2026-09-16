#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -n "${PRISM_BIN:-}" ]]; then
  OUTPUT="$PRISM_BIN"
elif [[ -d /opt/prism/bin ]]; then
  OUTPUT="/opt/prism/bin/prism"
else
  OUTPUT="$ROOT/bin/prism"
fi

mkdir -p "$(dirname "$OUTPUT")"
go mod download
go build -trimpath -o "$OUTPUT" ./cmd/prism
printf 'Built %s\n' "$OUTPUT"
