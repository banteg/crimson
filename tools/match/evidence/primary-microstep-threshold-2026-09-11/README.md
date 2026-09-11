# Primary movement threshold and collision cadence

Native primary projectiles accumulate movement until the vector length reaches
four units or the microstep budget ends. Python used a double-precision length
at that branch. The native x87 PC24 length can round to exactly four while the
double result remains below four, delaying Python's movement and collision
checks. The correction uses the existing `x87_pc24_hypot` at this one threshold.
The C++ reconstruction and Zig runtime already preserve the measured behavior.
No matching source, matcher, global vector method, or matching score changes.

In case 22, the accumulated vector is
`(-0.7636322975158691, -3.926431655883789)`. Its old double length is
`3.99999997926696`; its native PC24 length is `4.0`. Native performs three
four-unit movements and collision checks. The old Python path first accumulates
eight units and performs only two checks. With the player positioned at the
first native check, native leaves 70 health while old Python leaves 80.

## Reproduce

From the repository root:

```sh
uv run --with unicorn==2.1.4 --with capstone python tools/match/evidence/primary-microstep-threshold-2026-09-11/verify.py --out /tmp/crimson-primary-microstep-proof
cmp /tmp/crimson-primary-microstep-proof/primary-microstep-threshold.json crimson-zig/src/runtime/testdata/primary-microstep-threshold.json
PYTHONPATH=. uv run python tools/match/evidence/primary-microstep-threshold-2026-09-11/verify_ports.py --native-results /tmp/crimson-primary-microstep-proof/witnesses.json --out /tmp/crimson-primary-python.json
PYTHONPATH=. uv run python tools/match/evidence/primary-microstep-threshold-2026-09-11/verify_ports.py --native-results /tmp/crimson-primary-microstep-proof/witnesses.json --out /tmp/crimson-primary-python-legacy.json --legacy-threshold
uv run pytest tests/gameplay/test_primary_microstep_native.py
cd crimson-zig && zig build test
```

The negative control temporarily substitutes the exact former
`sqrt(x*x + y*y)` expression at the sole primary-threshold helper call site.
It requires failing cadence witnesses and leaves the source untouched. It
does not modify global vector arithmetic or replace movement/collision logic.

## Native execution and observed effects

The runner extends the particle-impact execution engine with the real native
`player_find_in_radius` body and explicit player records. Native vector addition,
creature lookup, player lookup, float conversion, and primary update execute as
machine code. Perk lookup returns zero; all creature slots are inactive. Native
player damage executes directly in the primary update body. Unknown transfers
or writes outside declared pools/globals and the stack fail. Each run checks
ESP, callee-saved registers, control word, and an empty x87 stack.

The first 500 PC24 cases use deterministic angles, positions, and speeds, with
frame times within two adjacent float values of `4 / (60 * speed)` and travel
budgets of 6, 9, or 12. The old Python port disagrees on collision cadence in
21 cases; only 17 have different final position bits. The four other cases
show why final-position checks alone miss observable collision behavior.

Each of those 21 seeds then gets five real-player cases: an unshielded player,
a shielded player, a dead player, owner exclusion, and shock-chain exclusion.
The player position comes from the first native lookup in its no-hit seed.
All 605 native/C++ pairs agree in every complete pool byte array, observed
global, ordered call, ordered non-stack write, and RNG state. Every case has a
full native observation digest; source/object/body/build identities, compiled
layout checks, and fixture hashes are recorded in `results.json`.

Python's verifier records each real spatial-query position while calling the
original query method and uses `_WorldStepRuntime` with the actual player-damage
helper. Corrected Python matches all 605 witnesses. The old-arithmetic control
fails 126 cases on cadence, including 21 incorrect player-health results.
The shared 156-case file retains the first 32 no-hit cases, every discovered
cadence counterexample, and all 105 player controls. Both ports check the
projectile fields, player state, and RNG; Python additionally checks each
collision-query position. Zig's implementation needs no correction.

This proof covers these PC24 primary-movement paths and player-hit branches.
It does not cover active-creature impact effects, every primary projectile
type, alternate control words, or whole-function equivalence. Native player
entity flags and the update tick are included in C++ byte comparisons but are
not asserted as port observables.

## Validation

The full Python suite passes with 3,490 tests, 13 skips, and 135 snapshots.
Zig Debug and ReleaseFast each pass 682 tests; native ReleaseFast and WebAssembly
builds pass. Ruff, type/import checks, documentation checks, Zig lint,
ast-grep rules/tests, strict experiment validation, current native closure,
and matching regression checks pass. The pre-change behavior was reproduced
against parent `7ec7c1918e110e24f267c6877b2712c1f5608e76` and by the preserved
old-arithmetic control.
