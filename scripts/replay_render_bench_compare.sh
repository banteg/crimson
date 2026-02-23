#!/usr/bin/env bash
set -euo pipefail

# Compare replay render benchmark outputs between classic and RTX modes.
#
# Usage:
#   scripts/replay_render_bench_compare.sh [REPLAY_FILE] [OUT_DIR]
#
# Examples:
#   scripts/replay_render_bench_compare.sh survival_20260223_165511_score7046201.crd
#   scripts/replay_render_bench_compare.sh ./artifacts/replays/foo.crd bench/my_cmp
#
# Notes:
# - Uses one measured run and zero warmup runs by default.
# - Saves benchmark JSON, full telemetry JSON, SVG charts, and stdout logs.
# - Charts require optional deps: uv sync --extra charts

REPLAY_FILE="${1:-survival_20260223_165511_score7046201.crd}"
OUT_DIR="${2:-bench/render_cmp_$(date +%Y%m%d_%H%M%S)}"

if [[ -z "$REPLAY_FILE" ]]; then
  echo "missing replay file path" >&2
  exit 1
fi

if ! uv run python -c "import altair, vl_convert" >/dev/null 2>&1; then
  cat >&2 <<'EOF'
missing chart dependencies.
run:
  uv sync --extra charts
EOF
  exit 1
fi

mkdir -p "$OUT_DIR/classic" "$OUT_DIR/rtx"

echo "replay: $REPLAY_FILE"
echo "output: $OUT_DIR"

uv run crimson replay benchmark "$REPLAY_FILE" \
  --mode render \
  --runs 1 \
  --warmup-runs 0 \
  --render-telemetry \
  --render-telemetry-out "$OUT_DIR/classic/telemetry.json" \
  --render-charts-out-dir "$OUT_DIR/classic/charts" \
  --json-out "$OUT_DIR/classic/benchmark.json" \
  | tee "$OUT_DIR/classic/stdout.txt"

uv run crimson replay benchmark "$REPLAY_FILE" \
  --mode render \
  --rtx \
  --runs 1 \
  --warmup-runs 0 \
  --render-telemetry \
  --render-telemetry-out "$OUT_DIR/rtx/telemetry.json" \
  --render-charts-out-dir "$OUT_DIR/rtx/charts" \
  --json-out "$OUT_DIR/rtx/benchmark.json" \
  | tee "$OUT_DIR/rtx/stdout.txt"

uv run python - "$OUT_DIR" <<'PY' | tee "$OUT_DIR/summary.txt"
import json
import pathlib
import sys

base = pathlib.Path(sys.argv[1])


def load(mode: str) -> dict[str, float]:
    payload = json.loads((base / mode / "benchmark.json").read_text(encoding="utf-8"))
    benchmark = payload["benchmark"]
    telemetry = payload["render_telemetry"]["summary"]
    return {
        "wall_ms_p50": float(benchmark["wall_ms"]["p50"]),
        "tps_p50": float(benchmark["ticks_per_second"]["p50"]),
        "realtime_x_p50": float(benchmark["realtime_x"]["p50"]),
        "frame_ms_p50": float(telemetry["frame_ms"]["p50"]),
        "draw_ms_p50": float(telemetry["draw_ms"]["p50"]),
        "draw_calls_p50": float(telemetry["draw_calls_total"]["p50"]),
    }


classic = load("classic")
rtx = load("rtx")

print("mode    wall_ms_p50  tps_p50  realtime_x_p50  frame_ms_p50  draw_ms_p50  draw_calls_p50")
for mode, values in (("classic", classic), ("rtx", rtx)):
    print(
        f"{mode:7} "
        f"{values['wall_ms_p50']:11.3f} "
        f"{values['tps_p50']:7.2f} "
        f"{values['realtime_x_p50']:14.2f} "
        f"{values['frame_ms_p50']:12.3f} "
        f"{values['draw_ms_p50']:11.3f} "
        f"{values['draw_calls_p50']:14.2f}"
    )

print()
print("delta (rtx - classic):")
print(
    f"wall_ms_p50={rtx['wall_ms_p50'] - classic['wall_ms_p50']:+.3f} "
    f"tps_p50={rtx['tps_p50'] - classic['tps_p50']:+.2f} "
    f"realtime_x_p50={rtx['realtime_x_p50'] - classic['realtime_x_p50']:+.2f} "
    f"frame_ms_p50={rtx['frame_ms_p50'] - classic['frame_ms_p50']:+.3f} "
    f"draw_ms_p50={rtx['draw_ms_p50'] - classic['draw_ms_p50']:+.3f} "
    f"draw_calls_p50={rtx['draw_calls_p50'] - classic['draw_calls_p50']:+.2f}"
)
PY

echo
echo "artifacts:"
find "$OUT_DIR" -maxdepth 3 -type f | sort
