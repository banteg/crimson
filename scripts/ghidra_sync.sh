#!/usr/bin/env bash
set -euo pipefail

# One-way sync of Ghidra outputs from WSL -> Windows repo, then clean WSL outputs.
#
# Usage:
#   scripts/ghidra_sync.sh [--skip-run]
# Env:
#   CRIMSON_WIN_REPO=/mnt/c/dev/crimson (default)

WIN_REPO="${CRIMSON_WIN_REPO:-/mnt/c/dev/crimson}"
SKIP_RUN=false

for arg in "$@"; do
  case "$arg" in
    --skip-run) SKIP_RUN=true ;;
    *) echo "Unknown arg: $arg" >&2; exit 1 ;;
  esac
done

if [[ ! -d "$WIN_REPO/.git" ]]; then
  echo "Windows repo not found at: $WIN_REPO" >&2
  exit 1
fi

if [[ "$SKIP_RUN" == false ]]; then
  just ghidra-exe
  just ghidra-grim
fi

rsync -a --delete \
  analysis/ghidra/raw/ \
  "$WIN_REPO/analysis/ghidra/raw/"

rsync -a --delete \
  analysis/ghidra/derived/ \
  "$WIN_REPO/analysis/ghidra/derived/"

if [[ -f analysis/ghidra/raw/ghidra_analysis.log ]]; then
  rsync -a analysis/ghidra/raw/ghidra_analysis.log "$WIN_REPO/analysis/ghidra/raw/"
fi
if [[ -f analysis/ghidra/raw/ghidra_output.log ]]; then
  rsync -a analysis/ghidra/raw/ghidra_output.log "$WIN_REPO/analysis/ghidra/raw/"
fi

git checkout -- analysis/ghidra/raw analysis/ghidra/derived
echo "Synced Ghidra outputs to $WIN_REPO and cleaned WSL outputs."
