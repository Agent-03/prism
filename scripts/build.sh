#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUTPUT="${PRISM_BIN:-$ROOT/bin/prism}"
mkdir -p "$(dirname "$OUTPUT")"
go mod download
go build -trimpath -o "$OUTPUT" ./cmd/prism
printf 'Built %s\n' "$OUTPUT"
