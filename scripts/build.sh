#!/usr/bin/env bash
# Everything, from public data to PDFs. This is what the GitHub Actions workflow runs, too.
#   scripts/build.sh                 # fetch -> scan -> analyze -> render -> lint -> build -> PDFs
#   SKIP_FETCH=1 scripts/build.sh    # reuse data/raw
#   SKIP_SCAN=1  scripts/build.sh    # reuse data/raw/scanners
#   SKIP_SLIDES=1 scripts/build.sh   # stop after rendering the markdown
# Needs: python3, podman or docker (scanners), node 22.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[ -x .venv/bin/python ] || { python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt; }
PY=.venv/bin/python

if [ -z "${SKIP_FETCH:-}" ]; then
  $PY scripts/fetch_kev_epss.py
  $PY scripts/fetch_cvelist.py
fi
[ -n "${SKIP_SCAN:-}" ] || scripts/scan_images.sh
$PY scripts/fetch_case_studies.py ${SKIP_FETCH:+--offline}
$PY scripts/analyze.py
$PY scripts/build_slidev.py
[ -z "${SKIP_SLIDES:-}" ] || exit 0

(cd slides && { [ -d node_modules ] || npm ci --no-audit --no-fund; } && npm run lint && npm run build && npm run export)
# Put each PDF next to its static site (the deck's download button points there).
for l in en pt-BR; do cp "slides/export/devopsdaysbsb2026-$l.pdf" "slides/dist/$l/"; done
