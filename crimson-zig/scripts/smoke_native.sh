#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <replay-path-or-name>" >&2
  exit 1
fi

replay="$1"

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
export ZIG_GLOBAL_CACHE_DIR="${ZIG_GLOBAL_CACHE_DIR:-$root_dir/.zig-cache-global}"

zig build

./zig-out/bin/crimson-zig replay verify "$replay" --format json > /tmp/crimson_zig_verify.json
uv run crimson replay verify "$replay" --format json > /tmp/crimson_py_verify.json

uv run python - <<'PY'
import json
from pathlib import Path

zig = json.loads(Path('/tmp/crimson_zig_verify.json').read_text())
py = json.loads(Path('/tmp/crimson_py_verify.json').read_text())

keys = (
    'schema_version',
    'status',
    'replay_sha256',
)
for k in keys:
    if zig[k] != py[k]:
        raise SystemExit(f'mismatch for {k}: {zig[k]!r} != {py[k]!r}')

rr_keys = (
    'game_mode_id',
    'tick_rate',
    'ticks',
    'elapsed_ms',
    'score_xp',
    'creature_kill_count',
    'most_used_weapon_id',
    'shots_fired',
    'shots_hit',
    'rng_state',
)
for k in rr_keys:
    if zig['run_result'][k] != py['run_result'][k]:
        raise SystemExit(f'run_result mismatch for {k}: {zig["run_result"][k]!r} != {py["run_result"][k]!r}')

print('native smoke ok')
PY
