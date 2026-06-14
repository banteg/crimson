#!/bin/sh
# Compile a scratch and diff it against an original Crimsonland function.
# Usage: tools/match/match.sh <scratch-dir> [extra crimson match diff args...]
set -eu

SCRATCH_DIR="$(cd "$1" && pwd)"
shift
MATCH_ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$MATCH_ROOT/../.." && pwd)"

IMAGE="crimsonland.exe"
FUNCTION=""
COMPILER="msvc7.0"
CFLAGS="/O2 /G6 /W3 /GR-"
SOURCE="scratch.cpp"
END=""
SYMBOL=""
. "$SCRATCH_DIR/scratch.conf"

: "${FUNCTION:?scratch.conf must set FUNCTION}"

BUILD_DIR="$SCRATCH_DIR/build"
mkdir -p "$BUILD_DIR"
cp "$SCRATCH_DIR/$SOURCE" "$BUILD_DIR/$(basename "$SOURCE")"

cd "$BUILD_DIR"
uv run crimson match validate "$(basename "$SOURCE")"
# shellcheck disable=SC2086
MSVC_VER="$COMPILER" "$MATCH_ROOT/cl.sh" /c $CFLAGS "$(basename "$SOURCE")"

OBJ="$BUILD_DIR/$(basename "$SOURCE" | sed 's/\.[^.]*$/.obj/')"
MATCH_ARGS=""
[ -n "$END" ] && MATCH_ARGS="$MATCH_ARGS --end $END"
[ -n "$SYMBOL" ] && MATCH_ARGS="$MATCH_ARGS --symbol $SYMBOL"

cd "$REPO_ROOT"
# shellcheck disable=SC2086
exec uv run crimson match diff "$OBJ" "$FUNCTION" \
  --image "game_bins/crimsonland/1.9.93-gog/$IMAGE" \
  --functions "analysis/ida/raw/$IMAGE/functions.json" \
  --metadata "analysis/ida/raw/$IMAGE/metadata.json" \
  $MATCH_ARGS "$@"
