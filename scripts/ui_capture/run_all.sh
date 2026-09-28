#!/bin/bash
# Capture every scenario from one checkout, 16 hidden game windows in parallel.
# usage: scripts/ui_capture/run_all.sh <checkout> <out_dir> [assets_dir]
set -u
here=$(cd "$(dirname "$0")" && pwd)
checkout=$(cd "$1" && pwd)
out=$2
assets=${3:-$checkout/artifacts/assets}
rm -rf "$out"
mkdir -p "$out"
out=$(cd "$out" && pwd)
run() { # name scenario size
  (cd "$checkout" && timeout 600 uv run python "$here/capture.py" "$here/scenarios/$2.py" "$out/$1" --size "$3" --assets "$assets" \
    >"$out/$1.log" 2>&1; echo "$1 exit=$? shots=$(grep -c '^shot' "$out/$1.log")") &
}
for scenario in menus menus_unlocked pause perk game_over quest quest_fail rush tutorial typo; do
  run "$scenario" "$scenario" 1024x768
done
for panel in play options stats; do
  run "small_640_$panel" "small_640_$panel" 640x480
  run "small_800_$panel" "small_800_$panel" 800x600
done
wait
