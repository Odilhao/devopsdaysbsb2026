#!/usr/bin/env bash
# Scan a container image with Trivy and Grype (run as containers via podman or docker)
# to show how much two scanners disagree on the same image.
#
# Usage: scripts/scan_images.sh [image ...]   (default: docker.io/library/node:20)
# Output: data/raw/scanners/<tool>__<image-slug>.json
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/data/raw/scanners"
CACHE="$ROOT/data/raw/scanner-cache"
mkdir -p "$OUT" "$CACHE/trivy" "$CACHE/grype"
ENGINE="$(command -v podman || command -v docker)"
TRIVY=docker.io/aquasec/trivy:0.58.1
GRYPE=docker.io/anchore/grype:v0.86.1

IMAGES=("${@:-docker.io/library/node:20}")

# Retry: scanner databases come from public registries that rate-limit now and then.
retry() { for i in 1 2 3; do "$@" && return 0; echo "retry $i: $*" >&2; sleep $((i * 20)); done; return 1; }

for img in "${IMAGES[@]}"; do
  slug="$(echo "$img" | tr '/:@' '___')"
  echo "== $img"
  retry "$ENGINE" run --rm -v "$CACHE/trivy:/root/.cache:Z" "$TRIVY" \
    image --quiet --scanners vuln --format json "$img" > "$OUT/trivy__${slug}.json"
  retry "$ENGINE" run --rm -v "$CACHE/grype:/root/.cache/grype:Z" "$GRYPE" \
    "$img" -o json -q > "$OUT/grype__${slug}.json"
done
echo "done: $OUT"
