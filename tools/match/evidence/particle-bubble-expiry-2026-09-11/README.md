# Bubble expiry re-enters inactive creature death handling

An attached Bubblegun particle calls `creature_handle_death(target, false)` on
expiry even when the target is already inactive. Only death-SFX selection and
playback are conditional on the target's active byte. The death handler emits
its forced-bonus and recent-death prelude before its own inactive early return.
Both runtime ports had incorrectly guarded the entire call, and Python's world
adapter added another inactive early return.

The correction moves the death call outside the sound guard in both ports and
lets Python's adapter enter the real handler. The adapter changes the recorded
owner only for active targets, as before. Invalid-index handling is preserved.
The matching C++ already expresses the correct branch structure, so this slice
changes runtime behavior without claiming a static matching gain.

## Reproduce

From the repository root:

```sh
uv run --with unicorn==2.1.4 --with capstone python tools/match/evidence/particle-bubble-expiry-2026-09-11/verify.py --out /tmp/crimson-bubble-expiry-proof
cmp /tmp/crimson-bubble-expiry-proof/particle-bubble-expiry.json crimson-zig/src/runtime/testdata/particle-bubble-expiry.json
uv run pytest tests/gameplay/test_particle_bubble_expiry_native.py tests/gameplay/test_death_timing.py
cd crimson-zig && zig build test
```

The runner is derived from the prior particle-impact execution runner. It adds
the real native `creature_handle_death` body to its executed helpers, observes
the three recent-death positions, and records the death counter and reward
flags at their verified widths. Native image SHA-256 and Unicorn version are
pinned. Compiled header checks verify pool dimensions and fixture field layouts.
The result includes source/object/body/build identities and fixture hashes.

All 224 cases use inactive targets with flags zero. They cross PC24/PC64,
initial death counts 0 through 6, one or three expiring bubbles, target slots 0
and 383, and independent initial fire-seen/handout flags. Repeated expiry calls
exercise position slots, clearing both flags when the counter reaches three,
and saturating the counter at six. All six gameplay pools, history positions,
observed globals, ordered calls, every non-stack write, and RNG state agree
between native execution and the current C++ candidate. No sound or RNG draw
occurs. Unknown control transfers and writes outside the declared memory fail;
ESP, callee-saved registers, x87 control word, and empty x87 stack are checked.

The 112 PC24 witnesses are exported directly for both runtime regressions.
Python executes particle update through `_WorldStepRuntime` and the real
`CreaturePool.handle_death`; it also checks the recorded death count and that an
inactive creature retains its owner. Zig executes its real `killNoCorpse`.
Against parent commit `8a2c119b9002b964ed486eaa0de40d330fc65a07`, all 112 Python cases failed: unsaturated history cases
missed updates, and saturated cases missed the death-handler invocation. The
Zig regression failed at its first history check. Both pass after the change.
The existing active, zero-HP bubble expiry test remains an audio/RNG control.

This matrix does not execute forced-bonus emission, active-target death side
effects, invalid native indices, or arbitrary pool states. Those are outside
this bounded proof; it does not establish whole-function or encoded equality.

## Validation

The full Python suite passes with 3,334 tests, 13 skips, and 135 snapshots.
Zig Debug and ReleaseFast each pass all 681 tests; the optimized native and
WebAssembly builds pass. Ruff, type/import checks, documentation checks,
ast-grep rules/tests, strict experiment validation, current native-closure
verification, and matching regression checks pass. No matching function source
changed in this slice.
