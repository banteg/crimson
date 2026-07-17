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
