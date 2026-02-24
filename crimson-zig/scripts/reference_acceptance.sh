#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <replay-path-or-name>" >&2
  exit 1
fi

replay="$1"

zig build
./zig-out/bin/crimson-zig replay verify "$replay" --format json > /tmp/crimson_zig_acceptance.json

uv run python - <<'PY'
import json
from pathlib import Path

payload = json.loads(Path('/tmp/crimson_zig_acceptance.json').read_text())
rr = payload['run_result']

expected = {
    'game_mode_id': 1,
    'tick_rate': 60,
    'ticks': 25803,
    'elapsed_ms': 398030,
    'score_xp': 76661,
    'creature_kill_count': 951,
    'most_used_weapon_id': 14,
    'shots_fired': 4566,
    'shots_hit': 1467,
    'rng_state': 2889720653,
}
for key, value in expected.items():
    got = rr[key]
    if got != value:
        raise SystemExit(f'acceptance mismatch {key}: {got!r} != {value!r}')
print('reference acceptance ok')
PY
