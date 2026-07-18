# creature_spawn_template WIP

Initial scope:

- shared root creature initialization
- random heading sentinel handling
- formation ids `0x11..0x19`
- spawn-slot controller ids `0x07..0x0e`, `0x10`
- random/stat template ids `0x03..0x06`, `0x1a..0x20`, `0x2e`,
  `0x31..0x36`, `0x3d`, `0x41`
- fixed-stat/special ids `0x00`, `0x01`, `0x0f`, `0x21..0x2d`,
  `0x2f`, `0x30`, `0x37..0x3c`, `0x3e..0x40`, `0x42`, `0x43`
- unhandled-template fallback for `0x11` and `0x13`
- shared post-dispatch tail modifiers

Known missing work:

- tighter local/field ordering in the dispatch ladder
- the `0x13` chain formation value objects are recovered, but its remaining
  field scheduling still differs
- tail modifier ordering/codegen still diverges after the large dispatch

Keep tracking prefix, not just total match percent. This scratch is expected to
be low percentage until more template families are added.

Current local score:

```txt
match=61.52% prefix=23/3159 target_insns=3159 candidate_insns=2950 refs=316/0/2
first_target=lea esi, dword [ebp+edx*2]
first_candidate=mov dword [esp+0x14], edi
```

Frame/prefix notes:

- The source now reproduces the native `0x48`-byte stack frame.
- Native allocates the root slot before resolving a `-100.0f` input heading,
  so the random-heading draw occurs after the allocation phase-seed draw and
  before the transient base-heading draw. The Zig runtime now preserves that
  order for every template emitted by a native creature spawn slot.
- Live disassembly at `0x00430b69..0x00430b72` shows the common template
  prologue clearing `creature+0x4c` (`force_target`) on the root immediately
  after allocation. The ring-child loop at `0x00430c47..0x00430d13` allocates
  and initializes children without touching that byte. Both ports therefore
  clear the template root while retaining native recycled-slot residue in
  formation children.
- The exact `creature_alloc_slot` body at `0x00428193..0x004281c7` clears only
  flags, the four-byte field at `+0x74`, and animation phase while seeding the
  phase word. In particular it preserves `orbit_angle` (`+0x84`) and the
  `orbit_radius`/projectile-type union (`+0x88`). Template `0x37` at
  `0x00433d41..0x00433dcd` enables ranged-variant fire without writing either
  field, unlike template `0x3c` at `0x00433a78..0x00433afd`. Both ports now
  retain those recycled values, and Zig mirrors both views of the native union.
- The common tail snapshots `health` into `max_health` at `0x00431114`, before
  applying any difficulty modifier. The hardcore block at
  `0x004311a1..0x004311c8` and retry ladder at
  `0x004340d3..0x004341b9` subsequently write current health (`+0x24`) but
  never max health (`+0x28`). Both ports now retain the unscaled base maximum;
  this matters to native health-ratio behavior rather than presentation.
- Live disassembly at `0x004311a1` proves the hardcore path first stores zero
  to the shared `quest_fail_retry_count` global, then applies the `1.05f`,
  `1.4f`, and `1.2f` stat multipliers. The ports now clear their live retry
  owner at the same spawn boundary. The Python front-end also forwards the
  failed-screen counter into each persistent `QuestMode` run; previously real
  Play Again runs always launched with zero and silently skipped the native
  retry easing ladder.
- The template-specific tail at `0x00431142..0x00431158` compares the spawn id
  with `0x38`, gates on hardcore, and multiplies move speed (`+0x5c`) by the
  `0.7f` stored at `0x0046f334`. This precedes the common hardcore `1.05f`
  multiplier at `0x004311a7..0x004311b0`. Zig now preserves both operations
  and their order; neighboring template `0x39` receives only the common buff.
- Moving the saved position pointer below the random-heading sentinel improved
  the prefix from `1/3159` to `20/3159`.
- The first blocker is now root-slot address arithmetic versus reloading `pos`
  from the stack.
- The Wibo-backed compile path makes this scratch practical enough to iterate
  on medium-size case families; the random-stat block added a large body match
  without moving the prefix.
- Moving the `0x13` chain formation ahead of the grid/fixed-stat ladder improved
  total body alignment from `55.06%` to `57.28%`; the prefix remains blocked at
  the same root-slot address arithmetic mismatch.
- In all four trigonometric child-spawn loops, materializing the allocated
  creature pointer before declaring the angle keeps the angle live on x87
  across the paired `cos`/`sin`, as native does. This removes six candidate
  instructions, raises the score from `58.09%` to `58.42%`, and improves the
  masked-reference audit from `308/1/2` to `311/1/2` without changing behavior.
- The five grid-spawn loops use the native inclusive vertical-offset guard
  `offset <= 0x100`. Replacing the equivalent `< 0x101` spelling recovers the
  native compare/branch tokens and raises the score from `58.42%` to `58.59%`.
- Native clamps the four tint components with the direct two-sided shape
  `if (x < 0) x = 0; else if (x > 1) x = 1`. Recovering that spelling across
  the three randomized template families fixes twelve clamp sites, removes six
  candidate instructions, raises the score to `59.06%`, and improves the
  reference audit to `314/1/2`.
- Binary Ninja and the IDA string inventory both identify `0x00477758` as the
  `"Unhandled creatureType.\n"` diagnostic. Naming that data object in the
  curated map replaces the address-derived scratch placeholder and resolves
  the remaining unknown masked reference (`315/0/2`).
- Binary Ninja's native stack view and the normalized listing show two adjacent
  16-byte tint values: the first formation root uses `[esp+0x38..0x44]`, while
  its child tint occupies `[esp+0x48..0x54]`. Modeling those as contiguous RGBA
  aggregates preserves the exact `0x48`-byte frame. Recovering the first root's
  whole-value assignment adds nine native-shaped construction/copy instructions
  and raises the score from `59.06%` to `59.31%` without changing the prefix or
  reference audit.
- Live disassembly shows the fixed-stat ladder repeatedly constructing RGBA in
  the same `[esp+0x48..0x54]` slot and copying the four dwords into the creature.
  This is the same value-object shape that gives the exact
  `survival_spawn_creature` scratch its tint assignments. Recovering it for the
  constant templates `0x21..0x2d`, `0x2f`, `0x30`, `0x3b`, and `0x3c` adds
  147 candidate instructions, raises the score from `59.31%` to `60.28%`, and
  preserves the exact frame, prefix, and `315/0/2` reference audit. Applying
  the shape broadly to later special cases perturbs VC6 register allocation and
  loses alignment, so those cases remain direct-field WIPs rather than being
  forced.
- The common tail operates on the current `creature` pointer, not necessarily
  the root allocated in the prologue. Formation loops leave that pointer on
  their final child before joining the effect/max-health/AI/difficulty tail at
  `0x0043108a..0x004311d2`; the root-only force-target clear remains at
  `0x00430b72`. Zig now tracks these as two distinct slots. In particular,
  template `0x12` buffs its final fallback child in hardcore, while template
  `0x0e` no longer applies the non-hardcore spawn-slot interval increase to its
  root spawner. The in-bounds spawn burst likewise uses the tail creature's
  position, matching the native `creature+0x14/+0x18` tests.
- Root initialization consumes and stores its transient `rand() % 314`
  heading at `0x00430b83..0x00430ba6`. Multi-creature formations leave that
  value on the root while the common store at `0x0043115b..0x0043115f` writes
  the requested heading only to the final child. Zig now retains both values
  instead of initializing every formation slot from the requested heading.
  Because template `0x0e` likewise leaves the root before the common
  `max_health = health` store, its root's recycled max-health field is now
  preserved rather than eagerly initialized; the last ring child still gets
  the common snapshot.
- Formation child heading writes are template-specific rather than an
  allocator default. The `0x13` chain loop at `0x00431348..0x0043143f` never
  touches `creature+0x2c`, so recycled headings survive until the common tail
  overwrites only the final child. Conversely, the `0x14` grid loop explicitly
  zeros that field at `0x0043154b`, as does the `0x0e` ring at `0x004320f6`.
  Both ports now distinguish preserved chain/ring-child residue from explicit
  zero initialization in grid and spawner-ring children.
- The `0x13` chain multiplies its cursor by the single-precision literal at
  `0x0046f70c` (`0x3eb2b8c3`, `0.3490658700466156f`) at `0x00431354`.
  Computing `20*pi/180` rounds one ULP lower (`0x3eb2b8c2`) before the x87
  multiply and visibly shifts the last child. Both ports now use the native
  literal and preserve the x87 PC=24 multiply/trig/add store boundaries; the
  analogous `0x11` literal is `0x3ec90fdb` at `0x0046f374`.
- The exact demo setup functions prove three additional live sentinel callers:
  `demo_setup_variant_0` (`0x00402ed0`) passes `-100.0f` to template `0x38`,
  while variant 1 (`0x004030f0`) passes it to `0x34` and `0x35`. Those paths
  now resolve the random heading between the allocator phase draw and transient
  base-heading draw, matching the universal prologue at
  `0x00430afc..0x00430ba6`. Variant 2's template `0x41` path already used that
  ordering and remains covered by the same regression table.
- A complete direct-xref audit shows that demos use the sentinel for `0x34`,
  `0x35`, `0x38`, and `0x41`, while `creature_update_all` uses it for every
  spawn-slot child. Survival and tutorial callers pass native pi instead, and
  demo variant 3 passes zero. The callee itself is nevertheless universal:
  after the root allocation at `0x00430afc`, the compare and optional
  `rand() % 628` at `0x00430b00..0x00430b3e` precede the transient
  `rand() % 314` initialization at `0x00430b83..0x00430ba6`, before any
  template dispatch. Zig now preserves that ordering for all 67 supported
  ids, including API-level combinations absent from native callers. A tagged
  RNG regression asserts the first two draws for every id, and the exhaustive
  Python/Zig diagnostic is clean in default, hardcore, retry, and sentinel
  scenarios (`0` mismatching templates in each).
- The native root initialization loads both position components before its
  zero-velocity store. Restoring that aggregate-like order raises the score
  from `60.28%` to `60.32%` without changing the frame, prefix, or references.
- A second live disassembly pass proves that the late `0x37`, `0x39`, `0x3a`,
  and `0x40` bodies also build RGBA in `[esp+0x48..0x54]` and copy the complete
  value into `creature+0x3c`. Recovering those four value assignments adds 34
  native-shaped instructions and raises the score from `60.32%` to `60.97%`,
  again preserving the `0x48` frame and `315/0/2` reference audit. The adjacent
  `0x38` and `0x00` cases and a broad late-ladder conversion were tested and
  rejected because they regressed alignment; only independently improving
  cases are retained.
- The `0x13` chain body at `0x00431217..0x00431445` exposes four reusable value
  shapes: zero velocity in `[esp+0x20..0x24]`, root/child position in
  `[esp+0x28..0x2c]`, orbit direction in `[esp+0x38..0x3c]`, and tint in
  `[esp+0x48..0x54]`. Modeling those as two-float and four-float aggregates
  recovers the native root construction and ten-child copy loop. A
  block-scoped signed cursor keeps the formation index plausible; reusing the
  typed position parameter as an integer scored slightly higher but was
  rejected as implausible source.
- Native template `0x42` at `0x00433fcc` also constructs its grey tint in
  `[esp+0x48..0x54]` before copying all four components. Converting that case
  independently adds eight native-shaped instructions and improves the global
  match, while the similarly evidenced `0x3e`, `0x3f`, and `0x43` conversions
  still perturb whole-function allocation and were rejected after isolated
  tests. Together the accepted `0x13` and `0x42` recoveries add 50 candidate
  instructions, raise the score from `60.97%` to `61.52%`, and improve the
  reference audit to `316/0/2` without changing the exact `0x48` frame or
  23-instruction prefix.
