#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <replay-path-or-name> [runs]" >&2
  exit 1
fi

replay="$1"
runs="${2:-5}"

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
export ZIG_GLOBAL_CACHE_DIR="${ZIG_GLOBAL_CACHE_DIR:-$root_dir/.zig-cache-global}"

zig build

uv run python - <<'PY' "$replay" "$runs"
import json
import subprocess
import statistics
import sys
import time

replay = sys.argv[1]
runs = int(sys.argv[2])


def bench(cmd):
    samples = []
    for _ in range(runs):
        t0 = time.perf_counter_ns()
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise SystemExit(f'command failed ({proc.returncode}): {" ".join(cmd)}\n{proc.stderr}')
        samples.append((time.perf_counter_ns() - t0) / 1_000_000.0)
    return statistics.median(samples)

py_cmd = ['uv', 'run', 'crimson', 'replay', 'verify', replay, '--format', 'json']
zig_cmd = ['./zig-out/bin/crimson-zig', 'replay', 'verify', replay, '--format', 'json']

py_ms = bench(py_cmd)
zig_ms = bench(zig_cmd)
speedup = py_ms / zig_ms if zig_ms > 0 else 0.0

print(json.dumps({'python_ms_p50': py_ms, 'zig_ms_p50': zig_ms, 'speedup': speedup}, indent=2))
if speedup < 3.0:
    raise SystemExit(f'perf gate failed: expected >=3.0x speedup, got {speedup:.3f}x')
print('perf gate ok')
PY
