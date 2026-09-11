# Native creature frame selection

Python and Zig now select shadow/body atlas frames directly from lifecycle and
animation state, with PC24 rounding before integer conversion. Both agree with
all **2,640 native witnesses**. The previous Python caller/helper path differs
on **270** witnesses. The previous Zig atlas path differs on **229 of 2,628**
comparable witnesses; its signed-mask implementation also panics in Debug on
a negative ping-pong input representing 12 excluded rows. The new implementation
handles all 2,640 rows in both Debug and ReleaseFast.

This corrects port behavior. The C++ matching source remains **79.737705%**,
760/765 instructions, `139/0/5` references, and neither normalized nor encoded
exact. No new function or matched byte is claimed.

## Concrete differences

The original renderer branches on `lifecycle_stage < 16`, then on its sign.
For nonnegative death staging it truncates the PC24-rounded value
`(base_frame + 15) - lifecycle_stage`. For a negative lifecycle it uses
`base_frame + 15`. Only the alive branch rounds `anim_phase + 0.5` and applies
the type's long-strip mirroring. The shock-frame offset follows all three
long-strip branches in the shadow and main passes.

- A spider with lifecycle `7.000000476837158` selects frame **24** at PC24.
  The old Python path selects **23**, having evaluated the subtraction in
  double precision. Under PC64, native also selects 23; that is a different
  precision contract, not evidence for retaining the Python result.
- A shock spider with lifecycle `-1` selects frame **63** for shadow/body.
  Zig previously returned **31** before applying the shock offset. Spawn
  template `SPIDER_BOSS_3A` supplies this species and flag combination.
- The phase immediately below `0.5f` rounds to `1.0f` when native adds `0.5f`
  at PC24; truncation therefore selects frame **1**, rather than Python's
  former frame 0.
- Trooper lifecycle `15.5` selects frame **0**. The former synthetic phase
  becomes negative and instead selects frame 15. Troopers are excluded from
  the native `creature_render_all` species pass; this is a direct-renderer
  diagnostic, not a demonstrated normal species-pass bug.
- Negative animation phases are tested separately from negative lifecycle.
  The former Zig sign-mask translation overflows at `INT_MIN - 1` for a
  ping-pong phase of `-17`; `@rem(raw, 16)` preserves the native signed
  remainder without this intermediate overflow. These phases are diagnostic;
  the fixture does not establish their occurrence during normal gameplay.

The native flash pass deliberately differs: a dying shock spider uses frame
31 there. The witness file retains `flash_frame`, but the port correction and
regressions compare shadow/body frames only. This does not implement or certify
the ports' flash pass, batch ordering, tint/alpha arithmetic, or GPU output.
The subsequent [hit-flash audit](../creature-hit-flash-2026-09-11/README.md)
implements the flash in both ports and extends the shared frame regressions
to check `flash_frame` as well.

## Evidence boundary

[verify.py](verify.py) executes the original `creature_render_type` and the
relocated current C++ object through the existing guarded
[runner](../creature-render-execution-2026-09-09/verify.py). The image and parent
runner hashes are pinned. The original CRT conversion executes unchanged;
Grim2D and the perk lookup remain modeled observers. Full ordered call records
and observed writes agree in all **36 scenarios**, covering 5,280 creature
observations across PC24 and PC64. The matrix executes 735/765 native and
730/760 candidate instructions. It targets frame selection and does not claim
complete function coverage or all-input equivalence.

[runner.py](runner.py) replaces only the fixture table's base-frame and mirror
fields before execution. [fixtures.py](fixtures.py) uses the values recovered
from `gameplay_reset_state`: bases 32/16/32/16/16/0 and mirror flags
0/1/0/1/1/0. The pinned image initially has zero in all six base/flag pairs;
the byte-exact reset reconstruction supplies the subsequent assignments.
Shared-header layout is compiled and checked. Twelve controls put
the original runner's table values through this adapter and reproduce its
complete native/candidate observations, including coverage and writes. Two
deliberately incorrect C++ controls are detected: omitting the dead shock
offset, and moving the alive threshold from 16 to 15.

The same stored inputs produce **126 different frame indices at PC64**.
The ports follow the repository's
[PC24 gameplay policy](../../../../docs/rewrite/float-parity-policy.md), also
supported by `grim_d3d_init`'s `CreateDevice` flags `0x20` without
`D3DCREATE_FPU_PRESERVE` (`0x02`). The precision-map introduction is corrected
to distinguish the earlier CRT startup setting from post-device gameplay.

[verify_ports.py](verify_ports.py) compares the shared native witnesses with
the actual current Python helper and compiled Zig `window_atlas` path. It
reconstructs the previous Python caller adaptation and loads the old helper
from immutable commit `76a92bf522e3ee8591fcbab324009201683d6dea`. It compiles
that commit's old Zig atlas/animation files in a private copy of unchanged
dependencies. Twelve diagnostic panic rows are listed explicitly; one is
executed separately and its actual integer-overflow failure is required.

[results.json](results.json) records native cases, call/write hashes, coverage,
negative controls, and input identities. [port-results.json](port-results.json)
records source hashes, every old mismatch, explicit exclusions, and both current
Zig build modes. The common
[witness file](../../../../crimson-zig/src/runtime/testdata/creature-frame-selection.json)
is consumed by Python and Zig tests. Python rendering integration tests also
inspect the texture source rectangles for three concrete boundaries.

## Reproduce

```sh
uv run --with unicorn==2.1.4 python \
  tools/match/evidence/creature-frame-selection-2026-09-11/verify.py \
  --out /tmp/crimson-creature-frame-selection-native
cmp /tmp/crimson-creature-frame-selection-native/witnesses.json \
  crimson-zig/src/runtime/testdata/creature-frame-selection.json
uv run python tools/match/evidence/creature-frame-selection-2026-09-11/verify_ports.py \
  --out /tmp/crimson-creature-frame-selection-ports
uv run pytest tests/creatures/test_creature_frame_native.py \
  tests/render/test_world_draw_order.py --no-cov
```

Run `zig build test --summary all` and
`zig build test -Doptimize=ReleaseFast --summary all` from `crimson-zig` for
the same embedded witnesses. Native execution on macOS requires Unicorn's JIT
memory allocation to be permitted.

The complete validation for this change passed 3,662 Python tests and 135
snapshots, 687 Zig tests in each build mode, native and WebAssembly builds,
native game-owned closure verification, and the matching checkpoint with no
regression or metadata errors. The atlas module is explicitly included in the
Zig library test root so these witnesses run under the standard test command.
