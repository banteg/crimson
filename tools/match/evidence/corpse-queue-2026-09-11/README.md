# Corpse queue witnesses

Zig's staged-death caller queued opaque white instead of the creature's tint,
and its queue omitted native alpha adjustment. Python retained the tint but
used double-precision direct division for nonzero transparency. Both ports
also imposed a minimum corpse size of one that the native caller does not use.

The ports now preserve the caller's tint and size, store float32 fields, and
apply the native alpha operation order at gameplay x87 PC=24 precision:
`alpha * 0.8f` when `cv_terrainBodiesTransparency` is zero, otherwise
`alpha * (1.0f / transparency)`. Division and multiplication round separately.
Zig frame batching appends the adjusted entry without attenuating it again.

## Evidence

[verify.py](verify.py) executes the original `fx_queue_add_rotated` body and
the compiled matching C body under Unicorn 2.1.4. No callback model executes
inside this helper. Its 240 cases cover counts 0, 1, 62 and 63; both terrain
texture failure states; six alpha values including zero, negative and above
one; and transparency 0, 0.3, 1, 2 and -1. Position, RGB, rotation and scale
include values that require float32 rounding.

For each execution the observer checks low-byte return value, count, every
written entry field, ordered non-stack writes, allowed instruction addresses,
preserved registers, stack balance, x87 control/tag words and unchanged
input/configuration memory. All other slots retain sentinels. Native and
compiled observations agree. The 64-element arrays permit 63 live entries;
full queues return false. Texture failure returns true without writing,
including when the queue is full. Invalid counters outside 0..63 are excluded;
the post-increment clamp's taken branch cannot occur from that valid domain.

The existing guarded creature-update runner additionally executes native and
compiled `creature_update_all` for 64 staged-death cases. They cover both gore
settings, successful/full queue responses, all four combinations of ping-pong
and long-strip flags, and sizes 0, 0.25, 40.3 and 130. Sizes below one are
well-defined diagnostics, not a claim that normal spawning produces them.
Both executions agree on complete observed pools, scalars, calls and writes.
Recorded queue arguments then feed the original queue body to obtain the
composed entry witness. These calls retain creature RGB and alpha, subtract
half its size from position, and select the special corpse ID 7 only for a
ping-pong strip without the long-strip flag. A rejected queue attempt restores
lifecycle to 0.001 and delays the kill-count increment. Gore-disabled cases
omit the queue attempt and complete this stage even with a full queue.

[results.json](results.json) records image/source/runner identities, queue
observation hashes, coverage and detected controls for missing attenuation,
direct division, white tint and the minimum-size clamp. The shared
[fixture](../../../../crimson-zig/src/runtime/testdata/corpse-queue.json)
checks actual Python and Zig queue implementations and creature updates.
A separate Zig live-runner test advances two simulation ticks in one frame
and checks that the presentation batch retains the once-adjusted tint.
The library test root now explicitly includes `live_runner`, whose tests had
only been referenced through a dependency module and were not executing.
Enabling its fifteen tests also exposed a temporary-pointer snapshot bug and
a pending-perk versus actual-pause reporting bug; both are fixed. Two existing
input/audio tests now establish aligned starting headings and an expired
weapon cooldown so they test input routing rather than native startup rules.

## Boundaries

The caller runner still models RNG, blood effects, sound and other callbacks;
the caller fixture checks corpse entries, lifecycle and kill count, not the
ping-pong blood burst's complete particle/RNG state. `cv_bodiesFade` is fixed
to one, matching the ports' current behavior. Nondefault transparency and
texture-failure options are helper APIs; this change does not wire console
variables into deterministic session configuration. No GPU or native Grim2D
rendering executes, and this does not establish packed-color or pixel parity.
The matching C/C++ sources are unchanged; no new matched function or byte is
claimed.

## Reproduce

```sh
uv run --with unicorn==2.1.4 python \
  tools/match/evidence/corpse-queue-2026-09-11/verify.py \
  --out /tmp/crimson-corpse-queue
cmp /tmp/crimson-corpse-queue/witnesses.json \
  crimson-zig/src/runtime/testdata/corpse-queue.json
uv run pytest --no-cov tests/creatures/test_corpse_queue_native.py
```

Run `zig build test --summary all` and `zig build test -Doptimize=ReleaseFast`
from `crimson-zig`. Unicorn needs JIT memory permission on macOS.
