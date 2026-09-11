# Particle impact arithmetic and fire-damage integration

This package extends the particle-update execution proof to actual creature hits.
The promoted source slice computes the bounce RNG scale once and restores the
final creature-displacement temporary. It remains a WIP: the separately recovered
SDK geometry still produces a different compiler alignment, and 25 PC64
angle-boundary cases remain in the narrower source slice.

## Reproduce

Run from the repository root with the existing VC6 toolchain:

```sh
uv run --with unicorn==2.1.4 --with capstone python tools/match/evidence/projectile-particle-impact-2026-09-11/verify.py --out /tmp/crimson-particle-impact-proof
PYTHONPATH=. uv run python tools/match/evidence/projectile-particle-impact-2026-09-11/verify_ports.py --native-results /tmp/crimson-particle-impact-proof/port-witnesses.json --out /tmp/crimson-particle-impact-python.json
uv run python tools/match/evidence/projectile-particle-impact-2026-09-11/export_regressions.py --native-results /tmp/crimson-particle-impact-proof/port-witnesses.json --out /tmp/particle-impact.json
cmp /tmp/particle-impact.json crimson-zig/src/runtime/testdata/particle-impact.json
uv run pytest tests/gameplay/test_particle_impact_native.py
cd crimson-zig && zig build test
```

`before.cpp` is the prior source, pinned by SHA-256. `recover.py` reconstructs the
single-scale control, promoted two-change candidate, and complete SDK-geometry
alternate without copying opaque generated assembly. `results.json` records
compiler/source/body identities, layout checks, native helper addresses, exact
case identities, comparison counts, coverage, and retained residual values.
The script writes full native witnesses and generated sources to the output
directory. It does not modify the canonical scratch.

## Native evidence

The first 1,200 cases cross the four valid particle styles, PC24/PC64, and three
collision modes: ordinary nearby targets, tint sums around native `1.6f`, and
near-equal deflection directions. A native no-hit preflight supplies the moved
particle position used to place the creature. The actual native
`creature_find_in_radius` then selects it; a failed hit is an assertion failure.
Thirty additional cases exercise negative and above-one color components on
both sides of the tint threshold.

The impact runner executes the native bodies of `crt_ftol`, `vec2_add`,
`vec2_add_inplace`, `creature_find_in_radius`, and `fx_spawn_sprite`. In the first
matrix, `creature_apply_damage` and `fx_queue_add_random` record their arguments
without running their effects. This isolates the caller's arithmetic and writes.
The second matrix executes both helpers and contains 663 PC24 cases: all 615
PC24 impact inputs plus 48 live/corpse and independent fire/bullet-perk cases.
`crt_rand` uses the native LCG and records every return address. Native
`fx_queue_add_random` initializes and updates its static color normally;
`crt_atexit` only records the registration.

Both matrices compare all six complete pool byte arrays, observed globals,
ordered callback arguments, RNG state, and every non-stack write. Every declared
pool size and accessed field offset/width is checked by compiling the live
headers. Unknown instructions/transfers and writes outside those pools, scalar
observations, and stack fail. Each run must restore callee-saved registers, ESP,
control word, and an empty x87 stack. The prior 4,817 no-hit cases also remain
identical in all observed dimensions for both recovered source candidates.

The native bounce code scales the integer draw by `0.1f` once, before multiplying
both stored velocity components. The old repeated source expression lets VC6
reassociate velocity, integer, and constant, changing PC24 rounding. Native final
creature displacement keeps the X product live and stores the Y product before
addition; the aggregate temporary recovers that boundary. These changes fix 148
of the original 173 failing state cases, and 153 of 178 after the explicit
color cases are included. The retained 25 PC64 cases originate in
the previous-position/hit-direction geometry: its source aggregate stores the
opposite component from native. The SDK-vector alternate fixes those cases too,
but its reference-problem count rises from 10 to 15, so it is preserved as an
explicit alternate rather than promoted through a weakened gate.

The verifier rejects newly failing fields in the narrower candidate. For each
retained failing field it records native, before, and recovered bytes. Those
values need not equal each other: fixing the final displacement can change a
creature position that still comes from the wrong deflection branch. Bytes
outside named fields must remain native-correct or retain the prior value.
Ordered-write differences are counted separately, including redundant in-range
tint stores and bubble field publication order. State agreement is not an
ordered-write or encoded-body equality claim.

## Runtime corrections

Python and Zig now round the collision vector operations at PC24 boundaries,
keep the `atan2` result wide until native wrap arithmetic, keep sine/cosine wide
until multiplication by 82, and apply the once-scaled RNG factor. RGBA clamping
runs only inside the native bright-tint branch. Python also uses the native
float literals and operation boundaries for decal grayscale and rotation.

Zig particle damage now takes the fire path, native kind 4. The previous bullet
path applied unrelated bullet perks and consumed heading-jitter RNG. Pyromaniac
now runs only for a positive-health target, matching the native helper's corpse
boundary. The compact shared fixture selects 135 independently generated native
cases, including every explicit color and damage-perk boundary. The complete
663-case Python comparison is also recorded. The Zig test was additionally run
against all 663 cases before selecting the smaller committed fixture.

The port comparisons check particle fields, representable creature position,
velocity, health, lifecycle, heading and tint, spawned sprites, decal arguments,
and complete RNG values/callers/state. Python additionally checks the damage
call arguments and hit-flash timer. Zig has no hit-flash field. Both ports omit
the native creature `state_flag`; this package does not claim that field is
unnecessary. Decal positions are converted from the ports' center representation
to native enqueue top-left coordinates for comparison.

## Limits

The final FX queue enqueue, sound output, and creature death handler remain
recording boundaries. The integrated cases include nonlethal live hits and
already-dead targets, not newly lethal death side effects. `perk_count_get` is an
explicit deterministic lookup, and player collision lookup returns no hit.
No whole-function correctness, complete impact-path coverage, runtime rendering,
encoded-body equality, or compiler ceiling is claimed by these finite cases.
