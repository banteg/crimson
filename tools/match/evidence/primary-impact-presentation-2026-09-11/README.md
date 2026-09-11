# Native primary-impact presentation

The Python and Zig ports reconstructed impact headings from `hit - origin`.
Native `projectile_update` instead subtracts its float32 half-pi constant from
the stored projectile angle. Rounded movement makes these differ even for
ordinary straight shots. The original also rounds each decal offset multiply
and add at PC24 precision.

The correction carries the projectile angle into presentation and recovers
those arithmetic boundaries. Python's optional `ProjectileHit.angle` preserves
decoding of older events and the fallback for callers that supply only points.
Zig passes the existing angle to its private presentation functions.

Executing the real native blood-splatter helper also exposed different float
constants and intermediate rounding in Python, an unsigned rotation subtraction
in Zig, and wrong RNG caller tags for Zig's second Bloody Mess coordinate pair.
The corrected ports preserve native splatter velocities, rotation, scale step,
and randomized decal output in the measured matrix.

## Evidence and results

`verify.py` executes the original x86 `projectile_update` at PC24, including its
real vector, collision, creature-damage, blood-splatter, and randomized-FX helper
bodies. Final `effect_spawn`, `fx_queue_add`, and audio calls are recorded
boundaries. Unknown control transfers and writes outside the declared observed
pools, globals, and stack fail. Every execution checks the stack, saved registers,
x87 control word, and empty x87 stack. Compiled header assertions verify the
pool layouts and every observed effect-template offset.

The executable SHA-256 is
`771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4`;
the runner requires Unicorn 2.1.4. `results.json` retains the native observation
digests, instruction coverage, helper identities, layouts, and witness hash.

The deterministic seed `2026091110` produces 1,000 nonlethal Pistol impacts.
Three origin arrangements—independent origin, initial spawn position, and
straight travel—are crossed with both violence settings and Bloody Mess on/off.
The collision target is placed using the actual native no-hit query. The
matrix varies angle, position, timestep, speed, RNG seed, pool slots, and
otherwise-unused template bytes. Damage uses the Pistol's float32 4.1 scale.
The initial shared template scale is explicitly one. The runner pins the
native `effect_defaults_reset` store at `0x0042dfa9` that writes this value to
`0x004ab1c8`; both core initialization and gameplay reset call that function.
This does not establish the shared template's full lifetime.

| Python comparison | Before | Corrected |
| --- | ---: | ---: |
| Cases with any checked difference | 959 | 0 |
| Cases with visible effect/decal differences | 501 | 0 |
| Randomized-decal input coordinates | 921 | 0 |
| Splatter input arguments | 474 | 0 |
| Spawned-effect fields | 501 | 0 |
| Final decal fields | 471 | 0 |

The baseline is commit `f245c98dcdfdd8511c5e62ead534d74cffb8cc51`.
All four executed baseline Python module hashes were checked against that
commit. `python-before.json` records hashes, failing indices, and group counts;
`python.json` records the corrected result. Projectile state, represented
creature state, damage-call arguments, shots-hit count, and tagged RNG output
already agreed and remain equal. The 458 additional cases counted by the
first row have gore disabled, so their differing decal inputs do not produce
visible decals.

Both Zig Debug and ReleaseFast pass the full 1,000-case matrix, including every
spawned-effect and final-decal field, represented projectile/creature state,
shots-hit count, and RNG value/caller/state. The committed Zig baseline fails
the same regression at witness zero. Zig does not expose native hit-flash or
state-flag fields, nor does this test intercept its private presentation or
damage-call arguments; those are not included in its equality claim.

The shared fixture file contains 120 cases: ten complete cycles of all twelve
combinations. All 3,610 Python tests pass, with 13 skips and 135 snapshots;
all 683 Zig tests pass. ReleaseFast executable and WASM builds pass.

This package does not establish PC64 port equivalence, effect-pool allocation
identity, audio-call argument equality, freeze/large-streak behavior, lethal
damage behavior, or whole-function completeness. It changes no C++ candidate
and earns no additional normalized or encoded matching credit.

## Reproduce

From the repository root:

```sh
uv run --with unicorn==2.1.4 --with capstone python tools/match/evidence/primary-impact-presentation-2026-09-11/verify.py --out /tmp/crimson-primary-presentation-full
uv run python tools/match/evidence/primary-impact-presentation-2026-09-11/verify_ports.py --witnesses /tmp/crimson-primary-presentation-full/witnesses.json --out /tmp/crimson-primary-presentation-full/python.json
uv run python tools/match/evidence/primary-impact-presentation-2026-09-11/export_regressions.py --witnesses /tmp/crimson-primary-presentation-full/witnesses.json --out /tmp/crimson-primary-presentation-shared.json
cmp /tmp/crimson-primary-presentation-shared.json crimson-zig/src/runtime/testdata/primary-impact-presentation.json
uv run pytest tests/gameplay/test_primary_impact_native.py
```

To measure the Python baseline, export its source into a temporary directory
and run the same observer with that source first on `PYTHONPATH`:

```sh
mkdir -p /tmp/crimson-primary-presentation-before
git archive f245c98dcdfdd8511c5e62ead534d74cffb8cc51 src | tar -x -C /tmp/crimson-primary-presentation-before
PYTHONPATH=/tmp/crimson-primary-presentation-before/src uv run python tools/match/evidence/primary-impact-presentation-2026-09-11/verify_ports.py --witnesses /tmp/crimson-primary-presentation-full/witnesses.json --out /tmp/crimson-primary-presentation-full/python-before.json --allow-differences
```

The Zig test accepts the complete generated witness file in place of the
120-case selection. Copy it to
`crimson-zig/src/runtime/testdata/primary-impact-presentation.json`, run
`zig build test --summary all` and
`zig build test -Doptimize=ReleaseFast --summary all` from `crimson-zig`, then
restore the deterministic selection with `export_regressions.py`.
