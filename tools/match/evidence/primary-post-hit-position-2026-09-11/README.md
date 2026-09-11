# Native post-hit positions and freeze shards

Native `projectile_update` reads the live projectile and creature positions for
post-hit presentation. Python retained the earlier collision snapshot after
stop jitter and Pulse Gun displacement. Impact sounds and freeze shards could
therefore use the wrong projectile position, while Pulse decals used the
creature's old position. The port now gives the post-hit presentation a fresh
position snapshot; the returned collision event and pre-hit splatter keep
their original positions.

Executing the real freeze-shard helper also exposed float constants and PC24
rounding differences in Python, premature trig rounding in Zig, and negative
zero from negating an already-converted zero RNG draw in both ports. Native
negates the integer first. Pulse Gun displacement now preserves the native
PC24 multiply and add boundaries in Python.

## Evidence and results

`verify.py` extends the pinned primary-impact presentation runner through the
actual native `effect_spawn_freeze_shard` body at `0x0042ec80`. It executes both
the original and canonical C++ candidate for 480 nonlethal impacts: the parent
120 inputs crossed with Pistol/Pulse Gun and Freeze off/on. The inputs already
span three origin arrangements, both gore settings, and Bloody Mess off/on.
The executable, parent input file, and parent engine source hashes are pinned.
The runner requires Unicorn 2.1.4 and retains the inherited stack, register,
x87, control-transfer, and write-boundary guards.

The native and C++ executions agree in all recorded pool state, globals, calls,
RNG state, and ordered writes for every case. `results.json` records those
comparison counts, instruction coverage, observation digests, the native
template scale-one reset instruction, and candidate identities. The witness
SHA-256 is `4c1436533d63c320860cc7e4e5a1c2d6cf5c307046c56fddad990e093cb7efec`.

| Python comparison | Before | Corrected |
| --- | ---: | ---: |
| Cases with any checked difference | 447 | 0 |
| Sound request arguments | 358 | 0 |
| Spawned-effect fields | 238 | 0 |
| Final decal fields | 60 | 0 |
| Randomized-decal input coordinates | 120 | 0 |
| Creature Y position bits | 6 | 0 |

The baseline is commit `944d2b1827bb10c3be44a6e757d7e1909202bda3`. All six
executed baseline Python module hashes were checked against that commit.
`python-before.json` records hashes, failing indices, and difference counts;
`python.json` records the corrected result. Audio comparison includes logical
bullet-hit sound selection, position, and gain. The native callback models
the loaded six-sound array as indices; it does not validate sound-file loading.

Zig Debug and ReleaseFast pass all 480 cases for represented projectile and
creature state, spawned-effect and final-decal fields, shots-hit count, and RNG
value/caller/state. The initial Zig regression failed on a one-ULP shard
velocity difference; correcting velocity exposed the separate signed-zero
scale-step difference. Zig's test does not observe audio or private helper
arguments, and its state does not represent native hit-flash/state-flag fields.

The committed shared fixture selects one complete 48-combination cycle and
includes the positive-zero scale-step control. All 3,658 Python tests pass,
with 13 skips and 135 snapshots; all 683 Zig tests pass. ReleaseFast executable
and WASM builds pass. The earlier 1,000-case Python presentation matrix also
continues to agree with its checked native observations.

This is a PC24, high-health, scale-one template proof. Effect allocation,
final FX enqueue, and audio implementations remain recording boundaries.
Other template histories, lethal damage, other projectile branches, and PC64
port behavior are outside this matrix. The C++ candidate remains at
66.287275% normalized similarity, with 435 resolved references and ten
reference problems; exact and encoded-body flags remain false. This slice
changes no C++ source and earns no additional matching credit.

## Reproduce

From the repository root:

```sh
uv run --with unicorn==2.1.4 --with capstone python tools/match/evidence/primary-post-hit-position-2026-09-11/verify.py --out /tmp/crimson-primary-post-position-full
uv run python tools/match/evidence/primary-post-hit-position-2026-09-11/verify_ports.py --witnesses /tmp/crimson-primary-post-position-full/witnesses.json --out /tmp/crimson-primary-post-position-full/python.json
uv run python tools/match/evidence/primary-post-hit-position-2026-09-11/export_regressions.py --witnesses /tmp/crimson-primary-post-position-full/witnesses.json --out /tmp/crimson-primary-post-position-shared.json
cmp /tmp/crimson-primary-post-position-shared.json crimson-zig/src/runtime/testdata/primary-post-hit-position.json
uv run pytest tests/gameplay/test_primary_impact_native.py
```

To measure the Python baseline with the same observer:

```sh
mkdir -p /tmp/crimson-primary-post-position-before
git archive 944d2b1827bb10c3be44a6e757d7e1909202bda3 src | tar -x -C /tmp/crimson-primary-post-position-before
PYTHONPATH=/tmp/crimson-primary-post-position-before/src uv run python tools/match/evidence/primary-post-hit-position-2026-09-11/verify_ports.py --witnesses /tmp/crimson-primary-post-position-full/witnesses.json --out /tmp/crimson-primary-post-position-full/python-before.json --allow-differences
```

For the full Zig matrix, temporarily copy the generated `witnesses.json` over
`crimson-zig/src/runtime/testdata/primary-post-hit-position.json`. Run
`zig build test --summary all` and
`zig build test -Doptimize=ReleaseFast --summary all` from `crimson-zig`, then
restore the deterministic 48-case selection with `export_regressions.py`.
