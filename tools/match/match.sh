#!/bin/sh
# Compile and diff one scratch through the same cached pipeline as status.
# Usage: tools/match/match.sh <scratch-dir> [extra crimson match scratch args...]
set -eu

SCRATCH_DIR="$(cd "$1" && pwd)"
shift
MATCH_ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$MATCH_ROOT/../.." && pwd)"

cd "$REPO_ROOT"
exec uv run crimson match scratch "$SCRATCH_DIR" --match-root "$MATCH_ROOT" "$@"
