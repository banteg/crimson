# Projectile residuals: primary and secondary paths

This continues the [particle decomposition](../projectile-residual-decomposition-2026-09-13/README.md)
from its frozen eleven-step candidate. It retains 46 independently reconstructible
experiments and a 22-step path through the primary and secondary residuals.
The canonical scratch remains unchanged. **No new exact function is claimed.**

The replayed candidate is `primary-f7-tick-before-scale`, source
`a51cbf5d23486f87dc6aaab6133adb0e9a7c73e9dafac1ffc98c7e70f2d3f298`, encoded body
`640dda74b56ca70297ae15f58db0fa2740a5ca1651fc4ecb06529ee63dfc096f`.
It has 2,196 instructions against 2,203 native, a `0xe4` frame against `0xf4`,
and six positional-reference problems. Both exactness gates remain false.

## Recovered boundaries

- Complete scaled decal, plasma and pulse vectors before adding their components
  to positions. The missing float materializations caused observable rounding
  differences; operand similarity did not reveal them.
- Use the actual position owners for primary distance, chain targets and Gauss
  effects. The primary position owner also restores several native register roles.
- Reload projectile type after effects and retain separate sound-call branches.
  This recovers native argument lifetime and conditional RNG placement.
- Convert jitter before multiplying trigonometric results. Reload the heading
  after calls on the Gauss freeze path.
- Keep the Bloody Mess range expression at each remainder operation. The named
  integer extended a live range and displaced the native creature-offset register.
- Construct the secondary burst direction before scaling. This fixes its cosine
  rounding boundary. Keep a separate normalized direction and scaled impulse.
- Compute explosion distance independently of the direction used for normalization.
  The direct helper expression recovers the native x87 arithmetic sequence there.

The graph includes rejected controls: equivalent commuted operands, a ternary
sound argument, mixed float/double impulse products, premature vector stores,
the SDK reciprocal-length form, and particle branch/owner changes. A changed
instruction count is not evidence that a rejected control is an improvement.
Only the ordered path is covered by the accumulated native replay receipts.

## Native execution

All 10,002 cases compare pools, selected globals, calls, writes and RNG state
against the original executable. Counts below are cases differing in each
observation category, not distinct bugs. The before column uses the canonical
source, before both this package and the preceding particle recovery.

| Suite | Cases | Before differences | Recovered differences |
| --- | ---: | --- | --- |
| Particle update | 4,817 | none | none |
| Particle impact | 1,230 | 25 state; 683 writes | none |
| Integrated particle impact | 663 | 336 writes | none |
| Bubble expiry | 224 | none | none |
| Primary movement | 1,000 | none | none |
| Primary impact | 1,000 | 70 calls | none |
| Expanded primary weapons | 576 | 1 state; 41 calls; 1 write | none |
| Rocket/minigun impact | 300 | 288 state; 291 calls; 293 writes | none |
| Explosion preservation | 192 | none | none |

The first six suites reuse their committed engines and fixture generators.
Their real-helper/recording boundaries are documented in the preceding package
and linked suite READMEs. `execute.py` extends the primary impact engine for
the final three suites: it executes native collision, nearest-creature and
sprite helpers and records the additional projectile, damage, FX and audio
boundaries. Spawned-projectile and other recorded helper bodies are not executed.
Unknown transfers and unmodeled writes fail the harness.

The expanded primary cases cover twelve projectile types, both x87 PC24 and
PC64, Bloody Mess and Freeze combinations, and three damage-pool values. The
rocket matrix covers secondary types 1 and 4; **it does not cover seeker steering**.
Explosion cases place five creatures inside, outside and near the damage radius.
External `D3DXVec2Normalize` uses a shared deterministic model and records input
bits. Its native DLL implementation is not executed or proven by these checks.

## Reproduce

Use the pinned image and compiler already required by the native matching setup.
Output directories should be new, short paths outside the source package.

```sh
uv run --no-sync python tools/match/evidence/projectile-primary-secondary-residuals-2026-09-13/audit.py \
  --out /private/tmp/pu-ps-audit
uv run --offline --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/projectile-primary-secondary-residuals-2026-09-13/verify.py \
  --suite primary-weapons --out /private/tmp/pu-ps-primary-weapons
```

Other suite names: `particle-update`, `particle-impact`, `particle-integrated`,
`bubble`, `movement`, `primary`, `rocket-impact`, `explosion`. Use a distinct output
directory per suite. The verification writes complete per-case observation
hashes; committed receipts omit these rows and retain their digest, fixture
digest, source/body/build identities, coverage and harness hashes.

`audit.py` rebuilds all 47 graph nodes, including the starting candidate, and
checks their recorded source/body identities. Local-window navigation preserves
register names, instruction order, internal branch topology, explained positional
references and consistent local stack-home renaming. It is **not an encoded-byte
comparison** or a proof of variable identity across windows. Windows with external
branches are deliberately left unmatched. Whole-function acceptance continues
to use the unmodified native matcher.

## Open work

Primary damage impulse still merges two products that native keeps separate.
Mixed float/double diagnostics approach that sequence but do not explain the
original source. Secondary creature induction and position ownership, speed
length arithmetic, seeker reloads, trail cosine materialization and burst
scheduling remain open. Particle flag reloads, threshold block layout, geometry
scheduling, loop endpoints and shared stack homes also remain unresolved.
The residual ledger records these separately; aggregate score does not select
the next experiment.
