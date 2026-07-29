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
- shared unhandled-template fallback reached by both ring formations, both
  chain formations, grid formations `0x14..0x17`, template `0x0f`, and unknown
  template ids
- shared post-dispatch tail modifiers

Known missing work:

- tighter local/field ordering in the dispatch ladder
- the `0x13` chain formation value objects are recovered, but its remaining
  field scheduling still differs
- residual register scheduling still diverges inside the hardcore modifier
  block after the large dispatch

Keep tracking prefix, not just total match percent. This scratch is expected to
be low percentage until more template families are added.

Current local score:

```txt
match=86.93% prefix=23/3159 target_insns=3159 candidate_insns=3161 refs=352/0/1
first_target=mov dword [esp+0x10], 0
first_candidate=mov dword [esp+0x14], 0
```

Frame/prefix notes:

- The source now reproduces the native `0x48`-byte stack frame.
- The function returns the current `creature_t *`, not an opaque pointer.
  Retyping both the return and its live `result` cursor in Binary Ninja turns
  the large dispatch from thousands of `result + offset` expressions into
  named `creature_t` fields without changing the generated body. The shared
  gameplay declaration now carries that return type to every recovered caller
  instead of repeating stale `void *` prototypes in individual scratches.
- Template `0x27` sets `BONUS_ON_DEATH` and treats `link_index` as the packed
  `creature_bonus_args_t`: signed low/high halfwords hold bonus id `3` and
  duration override `5`. The canonical creature union now exposes that overlay
  directly; the spawn, tutorial, and death scratches share it instead of
  reconstructing the two halfwords with casts or byte offsets.
- Native allocates the root slot before resolving a `-100.0f` input heading,
  so the random-heading draw occurs after the allocation phase-seed draw and
  before the transient base-heading draw. The Zig runtime now preserves that
  order for every template emitted by a native creature spawn slot.
- Live disassembly at `0x00430b69..0x00430b72` shows the common template
  prologue clearing `creature+0x4c` (`force_target`) on the root immediately
  after allocation. The ring-child loop at `0x00430c47..0x00430d13` allocates
  and initializes children without touching that byte. Both ports therefore
  clear the template root while retaining native recycled-slot residue in
  formation children. The field is now consistently typed as one byte in the
  shared header and live Binary Ninja structure, so the root write no longer
  needs a local byte reinterpretation.
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
- The common prologue at `0x00430b59..0x00430b66` copies the two adjacent
  position dwords from `[edi]` and `[edi+4]` before either velocity store,
  which is the code shape of the game's two-float value assignment rather
  than two independent scalar expressions. Recovering that aggregate copy
  also lets VC6 use `esi` for the native root-slot address arithmetic.
  Removing the now-dead explicit union write leaves only the compiler-required
  root byte-offset spill used by the later chain link. Together these changes
  raise the score from `61.52%` to `61.70%` with 2,954 candidate instructions,
  preserve the exact `0x48` frame and 23-instruction prefix, and leave the
  masked-reference audit at `313/0/2`.
- The common difficulty tail at `0x00431162..0x004311a1` is two independent
  decisions, not one `if/else`: native first tests `!hardcore` for the
  ping-pong interval increase, then reloads the global hardcore byte before
  choosing the modifier or retry path. Its three interval updates also
  materialize a `creature_spawn_slot_t *` before storing. Recovering those
  source shapes reproduces the second global load, both pointer-based stores,
  and the outlined retry entry; the retry clamp at `0x004341c5..0x004341f6`
  now has the same instruction order as native. The score rises to `61.82%`
  with 2,959 candidate instructions and the reference audit improves to
  `314/0/2`; only local scheduling inside the hardcore multiplier block still
  differs.
- A complete stack-use map shows the native prologue's three low locals are a
  two-float zero-velocity value in `[esp+0x10..0x14]` and the root creature's
  byte offset in `[esp+0x18]`. The previous scratch instead saved the position
  pointer because the `0x11` chain and five grid formations reused `pos` as a
  signed integer cursor. Recovering explicit signed formation offsets lets VC6
  retain the original position in `edi`, while the zero velocity now uses the
  same constructor-expression shape as the exact `survival_spawn_creature`
  scratch. This removes 22 candidate instructions, raises the score to
  `63.94%`, improves the prefix to 26 instructions and references to
  `316/0/2`, and preserves the exact `0x48` frame. VC6 still assigns the root
  byte-offset spill before the two value slots (`0x10` versus native `0x18`),
  so the remaining first mismatch is honest local-slot allocation rather than
  missing gameplay.
- Live Binary Ninja xrefs to the diagnostic block at `0x00431094` include the
  ring exits at `0x00430d19` (template `0x12`) and `0x00430eb6` (template
  `0x19`), followed by the `0x14..0x17` grid exits and the `0x0f` path. The
  block stores alien type `2` at `creature+0x6c` and `20.0f` at
  `creature+0x24` before joining the common max-health tail. Both ring cases
  now retain that surprising fallthrough, and both ports apply it to the final
  allocated child. Template `0x19` had previously left that child at
  `220/220`; its plan snapshot was updated to the proven native `20/20`.
- The same `0x19` loop stores `ebp` to each child's link field at
  `0x00430df9`; the prologue at `0x00430af7..0x00430b06` proves `ebp` is the
  root slot returned by `creature_alloc_slot`. Zig now links children to the
  actual root slot instead of hardcoding zero, with a regression that occupies
  slot zero before spawning the ring.
- The first ring's child loop loads a zero two-float value and a four-float
  RGBA value from the stack before copying them into each allocated creature.
  Recovering those source-level aggregates adds 13 candidate instructions.
  The independently measured aggregate shape reached `64.07%`; retaining the
  two native fallback edges changes block placement and settles the honest
  combined scratch at `63.91%`. The semantic edges are kept despite that small
  normalized-score decrease rather than being fakematched away.
- A focused revisit of template `0x13` at `0x00431217..0x00431445` recovered
  two further source-order details. The root formation writes its computed
  two-float position before assigning `max_health` and `ai_mode`; putting the
  value copy first reproduces native's exact `ecx`/`eax` store sequence at
  `0x00431329..0x00431345`. In the child loop, the shared `60.0f`
  health/reward/max-health group follows the position and velocity values
  rather than splitting the trigonometric construction.
- Native also keeps the scaled child X orbit direction in the distinct
  `[esp+0x30]` float temporary while the unscaled cosine remains at
  `[esp+0x38]`. Naming that previously anonymous local recovers the exact x87
  store/reload sequence at `0x0043139d..0x004313ab`. Together the three
  natural changes raise the whole-function score from `63.91%` to `64.53%`
  with the same 2,950 candidate instructions, exact `0x48` frame,
  26-instruction prefix, and honest `316/0/1` reference audit. Direct scaled
  expressions and scalarized child-vector writes were tested and rejected
  because they reduced both alignment and candidate coverage.
- Binary Ninja's outgoing edges show that the `0x12`, `0x19`, `0x11`, `0x13`,
  grid-family, and `0x0f` handlers are independent pre-dispatch tests. Their
  completed bodies all jump to the same diagnostic/default block at
  `0x00431094`, while the ordinary template ladder begins separately at
  `0x00431a7d`; an unknown id reaches that same default block from
  `0x0043403d`. Recovering those independent handlers and one shared final
  `else` removes duplicated source-level fallback bodies and reproduces the
  native block topology. The function rises from `64.53%` to `72.69%`, drops
  from 2,950 to 2,933 candidate instructions, and improves the masked-reference
  audit from `316/0/1` to `341/0/1`, while preserving the exact `0x48` frame
  and 26-instruction prefix. Repository fuzzy-weighted coverage gains 1,150
  bytes in both the all-image and Crimsonland-only totals.
- The late special-template bodies expose a consistent field order in live
  disassembly. Templates `0x00`, `0x38`, `0x37`, `0x39`, and `0x3a` store
  their creature type and control metadata before health, speed, reward, tint,
  size, and contact damage. In particular, the three timer/ranged templates
  write flags and link state before constructing their RGBA value, and `0x3a`
  writes its orbit/projectile metadata before the stat body. Templates `0x3f`
  and `0x43` also construct tint in `[esp+0x48..0x54]` and copy the complete
  value. Recovering those natural per-template sequences raises the score from
  `72.69%` to `73.74%`, adds 21 native-shaped candidate instructions, preserves
  the exact frame, prefix, and `341/0/1` reference audit, and gains another
  149 repository fuzzy-weighted bytes. Whole-value conversions for `0x3e` and
  the ordinary macro ordering for `0x00` were retested in this aligned ladder
  and rejected because they reduced both normalized and fuzzy coverage.
- Native grid templates `0x14..0x18` construct reusable two-float zero
  velocity, two-float child position, and four-float root/child tint values
  before copying them into each allocated creature. Recovering those shared
  value-object shapes across the five repeated formations adds 128
  native-shaped candidate instructions, raises the score from `73.74%` to
  `74.76%`, preserves the exact `0x48` frame, 26-instruction prefix, and
  `341/0/1` reference audit, and gains 144 fuzzy-weighted bytes. The three
  pieces were also probed independently; each perturbs VC6 allocation and
  regresses, while their coherent combination improves every grid region.
  Aggregate rewrites for template `0x0f` and the second ring remain rejected
  because they lose fuzzy coverage and resolved references.
- The eight spawn-controller templates materialize one
  `creature_spawn_slot_t *` after allocation and initialize the timer record
  through that pointer. This reproduces native's single scaled table `lea`
  followed by member stores instead of repeated indexed global expressions.
  The shared source shape removes four candidate instructions, raises the
  score from `74.76%` to `77.09%`, improves the reference audit from
  `341/0/1` to `349/0/1`, and gains 328 fuzzy-weighted bytes. A pointer for
  the later template `0x00` scheduler was independently tested but perturbs
  VC6 allocation across the aligned ladder and was rejected.
- In the `0x13` chain child, the tint value assignment precedes reward and
  max-health in source even though VC6 schedules the copy after those stores.
  Recovering that source order aligns the native health/position/velocity/tint
  sequence at `0x004313c2..0x00431403`, raises the score from `77.09%` to
  `77.38%`, and gains 41 fuzzy-weighted bytes without changing instruction
  count, frame, prefix, or references. Moving the root tint earlier and three
  alternative stat orders were measured separately and rejected.
- The five grid roots assign health after constructing their tint value but
  before copying it, while each grid child assigns max-health after its tint
  copy. VC6 interleaves those ordinary statements into the native repeated
  root and child schedules. Recovering both shared orders raises the score
  from `77.38%` to `80.36%` and gains 420 fuzzy-weighted bytes with the same
  3,078 candidate instructions, exact frame, prefix, and `349/0/1` reference
  audit. Root reward/speed permutations and tint-before-health child order
  were independently probed and rejected.
- The `0x12` ring child likewise assigns health before copying its tint value.
  That source order reproduces native's interleaved collision, health, tint,
  and max-health stores, raises the score from `80.36%` to `80.81%`, and gains
  63 fuzzy-weighted bytes with the same 3,078 candidate instructions, exact
  frame, prefix, and `349/0/1` reference audit. Three plausible placements of
  the collision flag compiled identically, so the retained form follows the
  native store sequence without introducing an artificial dependency.
- Template `0x11` constructs separate root and child tint values plus reusable
  child-position and zero-velocity pairs. Its chain loop also keeps unscaled
  cosine at `[esp+0x30]` and scaled X at `[esp+0x38]`, the opposite lifetime
  assignment from template `0x13`. Recovering those values reproduces native's
  x87 sequence and stack map through the loop, adds 28 candidate instructions,
  improves the reference audit to `350/0/1`, and raises the score from `80.81%`
  to `80.89%` while gaining 12 fuzzy-weighted bytes. The coherent root shape
  was retained with the stronger child recovery because live disassembly
  proves all eight constructor stores; scalar and reversed-temporary variants
  were measured and rejected.
- Every native caller passes the address of an adjacent X/Y pair, and the
  callee only reads offsets zero and four from that parameter. Recovering it as
  `const vec2f_t *` replaces all `*pos`/`pos[1]` aliases with named `x`/`y`
  fields in both source and Binary Ninja. A whole-function shadow probe is
  exactly neutral: 3,106 instructions, `80.89%`, a 26-instruction prefix, and
  references `350/0/1`. The shared declaration and all recovered callers now
  carry that immutable vector contract without changing their machine code.
- Live disassembly at `0x00433b87..0x00433c9c` proves that template `0x3e`
  constructs a complete RGBA value and template `0x00` materializes one
  `creature_spawn_slot_t *` after storing the allocated slot index. Each shape
  had perturbed allocation when tested alone earlier, but recovering the two
  linked lifetimes together raises the score from `80.89%` to `81.75%`, adds
  eight candidate instructions, and improves the reference audit to
  `351/0/1`.
- The independent pre-dispatch ladder tests template `0x0f` at `0x00431ba8`
  before template `0x18` at `0x00431c37`; the scratch had those two handlers
  reversed. Restoring the native branch order removes the largest remaining
  control-flow gap and raises the score to `82.19%` without changing behavior.
  With that lifetime order in place, the previously rejected complete tint
  value for `0x0f` becomes an improving recovery and raises the score again to
  `82.23%`.
- Template `0x19` likewise constructs its root tint in the shared typed value
  slot at `[esp+0x38..0x44]`; replacing four integer bit-copy aliases with one
  `creature_tint_t` assignment improves the aligned function. Its loop's
  `[esp+0x10..0x14]` zero velocity and `[esp+0x38..0x44]` child tint are now
  expressed as typed values rather than raw local-slot and integer aliases.
  The zero-vector lifetime moves a few unrelated scheduled instructions and
  leaves the honest combined score at `82.22%` with 3,136 candidate
  instructions; it is retained because the native stack construction and
  paired member loads prove the source object shape.
- Template `0x41` keeps its randomized size value live on x87 while deriving
  health, speed, and reward at `0x004324c8..0x00432514`. Recovering that
  short-lived scalar instead of reloading `creature->size` for each expression
  removes one candidate instruction, raises the score to `82.36%` with 3,135
  candidate instructions, and gains 20 fuzzy-weighted bytes without changing
  the exact frame, prefix, or `351/0/1` reference audit.
- The adjacent random-stat templates `0x31..0x34` use the same short-lived size
  value to derive health. Native stores size with a non-popping x87 write at
  `0x0043258c`, `0x00432632`, `0x004326e0`, and `0x004327a5`; retaining the
  scalar across each following health expression removes three more candidate
  instructions. The coherent four-case recovery raises the score to `82.50%`
  with 3,132 candidate instructions and gains 19 fuzzy-weighted bytes, again
  preserving the frame, prefix, and reference audit.
- Templates `0x1a`, `0x1b`, `0x1c`, `0x31`, `0x32`, `0x3d`, and `0x41`
  each derive multiple color channels from one random tint scalar. Native keeps
  that value on x87 across the adjacent component stores rather than reloading
  a creature field and copying its integer bits. Recovering the seven
  short-lived values removes six candidate instructions, raises the score to
  `82.93%` with 3,126 candidate instructions, and gains 60 fuzzy-weighted bytes
  without changing the frame, prefix, or `351/0/1` reference audit.
- Template `0x20` retains its randomized size across the immediately following
  health calculation at `0x00432866..0x00432879`. Recovering that scalar
  removes one candidate instruction, raises the score to `82.97%` with 3,125
  candidate instructions, and gains six fuzzy-weighted bytes. The same spelling
  was neutral for the neighboring random-stat cases and was not applied there.
- The `0x12` ring root constructs its tint before assigning health, but copies
  the completed RGBA value after that health assignment. VC6 then interleaves
  the four component copies with the root's type, health, speed, reward, size,
  damage, and max-health stores at `0x00430bd6..0x00430c18`. Recovering that
  ordinary source order raises the score from `82.97%` to `83.26%` and gains
  40 fuzzy-weighted bytes without changing instruction count, prefix, or
  references. Placing the copy after speed, reward, or size compiled
  identically; later placements and three stat permutations scored lower, so
  the retained spelling is the earliest equivalent and agrees with the
  already recovered `0x12` child ordering.
- The `0x19` ring root has the same source-level lifetime: its health
  assignment precedes the typed tint copy even though VC6 interleaves both
  with the remaining root statistics at `0x00430d31..0x00430d73`. The
  symmetric recovery raises the score from `83.26%` to `83.55%` and gains
  another 40 fuzzy-weighted bytes with unchanged instruction, prefix, and
  reference counts. Copy placements after speed, reward, and size were
  machine-code equivalent, so the earliest health-before-copy spelling again
  preserves the strongest common source shape.
- Native template `0x19` reuses the root tint's `[esp+0x38..0x44]` RGBA
  value for the child loop and builds each child's final position in the
  shared two-float position temporary before copying it. Reusing `tint`
  instead of a separate child color, assigning the complete typed value after
  health, and routing the summed orbit coordinates through `chain_position`
  recover those two object lifetimes. The coherent change adds 13
  native-shaped instructions, resolves two more references, raises the score
  from `83.55%` to `84.87%`, and gains 186 fuzzy-weighted bytes. An explicit
  extra position local exceeded the native frame and failed to compile; a
  separate child tint and scalar component copies both scored lower and did
  not explain the proven shared stack slot.
- Both ring formations express their induction update at the bottom of the
  child body. This agrees with native's increment/compare loop edges while
  allowing VC6 to delay the index spill until the surrounding initialization
  permits it. Restoring that ordinary loop shape gains four fuzzy-weighted
  bytes in template `0x12` and is byte-neutral in template `0x19`; the latter
  is retained because it compiles identically and removes the misleading
  mid-body update from the recovered source.
- The `0x0e` spawner ring constructs reusable zero velocity at
  `[esp+0x28..0x2c]` and RGBA at `[esp+0x48..0x54]` before its 24-child loop,
  then copies both complete values into each creature. Recovering those typed
  values, placing the tint copy after health/max-health, and moving the loop
  increment to the bottom adds 11 native-shaped instructions, raises the score
  from `84.90%` to `85.73%`, and gains 118 fuzzy-weighted bytes. Velocity-only
  and tint-only probes both disturbed more resolved references and scored
  lower; the coherent pair leaves the audit at `352/0/1`, one aligned
  reference below the previous scratch, while materially improving the proven
  object and loop shape.
- Four late template bodies still hid native source ordering behind generic
  stat macros. Template `0x01` establishes its split flag and size before the
  stat/tint group; `0x27` constructs tint around the bonus flag and reward,
  then writes the packed bonus arguments before size and damage; `0x3c`
  initializes ranged flags, orbit angle, and projectile type before its
  ordinary stat body; and `0x3f` keeps the tint value alive across speed and
  reward assignment. Recovering those case-specific sequences, plus the same
  evidenced value lifetime in `0x28` and `0x2b`, raises the score from `85.73%`
  to `86.46%`. The `0x27` and `0x3c` bodies now align instruction-for-
  instruction aside from inherited branch labels, while the `0x3f` recovery
  restores the native tint-copy body and leaves only VC6's opposite suffix-
  merging decision. The exact `0x48` frame, 26-instruction prefix, and
  `352/0/1` reference audit are unchanged; candidate length is now 3,161
  instructions against the native 3,159.
- The compiler-facing stack overlay no longer exposes the earlier decompiler
  fallback as parallel `int[15]` and `float[15]` arrays or addresses its first
  word through `slot_10_i`. Every used byte now belongs to a named value:
  `formation_offset`, zero velocity, chain position, scaled orbit X, the
  tint/orbit-direction union, and child tint. The formation offset's two
  observed lifetimes drive the grid X walk and the `0x13` chain angle index.
  A shadow compile is byte-identical at 86.46%, 3,161/3,159 instructions, and
  `352/0/1` references, so this removes scratch-era offset plumbing without
  steering VC6 or claiming a score improvement.
- The common prologue's root velocity is now a named two-float value whose
  lifetime begins after root allocation and sentinel-heading resolution, just
  before the root field stores. This is the native source-level aggregate
  shape already used for formation velocities, and it gives VC6 an explicit
  local lifetime instead of lowering an anonymous temporary.
  The score rises from `86.46%` to `86.93%`, gaining 66.93 fuzzy-weighted
  bytes with the same 3,161/3,159 instruction counts and `352/0/1` reference
  audit. The matched prefix moves from 26 to 23 instructions because the
  remaining compiler residual assigns the two zero words to the opposite pair
  of low stack slots; declaring the value before allocation scored lower and
  reduced the prefix to 5, while declaring it after the first root field was
  byte-identical to the old anonymous temporary.

## Binary Ninja control-flow recovery

The default analysis-time limit had discarded all IL for this 14,099-byte
game-core function. Its name-map row now requests `never_skip` analysis.
Reanalysis completes in about four seconds and recovers 260 basic blocks with
LLIL, MLIL, and HLIL. The resulting decompilation uses one typed
`creature_t *result` throughout the template dispatcher and contains no
`field_0xNN` or `__offset` placeholders. The few temporary tint pointers are
honest addresses of the `tint_r` member used by MSVC's four-byte copy lowering,
so they are not mislabeled as owning creature pointers.

This database-only control-flow recovery does not change code generation.
After the later source-order recoveries above, the scratch is 86.93% with
3,161/3,159 instructions and `352/0/1` references.

## Creature aggregate member recovery

All record-base position, target-offset, and tint accesses now name the
canonical `creature_t::position`, `target_offset`, and `color` components.
This removes the remaining flattened compatibility aliases from the
3,161-instruction switch while preserving the then-current 86.46% score and
26-instruction prefix,
and `352/0/1` references byte-for-byte. Combining the six paired position
stores into whole-vector assignments was also measured, but added one
instruction and lost 6.39 fuzzy-weighted bytes, so the evidenced independent
stores remain.

## Compiler profile and opening-region probes

A fresh compiler/flags matrix keeps VC6.5 `/O2 /GB` at the top:
86.9304%, 3,161/3,159 instructions, a 23-instruction prefix, and `352/0/1`
references. VC6.6 emits the identical body, while VC6.0 falls slightly to
86.8671%. `/G5`, `/TP`, and `/GX` are byte-neutral for their compiler family;
none of the tested `/G6`, `/O1`, `/Oy-`, Processor Pack, or VC7 variants beats
the canonical result.

The first mismatch is still the native low-slot permutation: zero velocity
occupies `[esp+0x10..0x14]` and the root byte offset `[esp+0x18]`, while VC6
assigns the same three words differently in the candidate. Splitting the
named velocity initialization around root-pointer formation was byte-identical.
Splitting its aggregate copy into the visibly separated `x` and `y` stores
instead grew the frame from `0x48` to `0x4c`, erased the prefix, and regressed
the whole function to 66.8461%. Both probes were reverted; the compact
two-float value remains the best natural source shape.

Two recorded mutation sweeps make the negative source-shape evidence
reproducible. The six-variant root-velocity sweep in
`prologue-mutations.json`
(`spec_sha256=4538a9abd9fcb294441c0b2f5436963ebdf1898a10b3fd1805359261f1429b21`)
found three split declaration/initialization spellings byte-identical to the
86.9304% baseline. Initializing the value before allocation lost 4.46
fuzzy-weighted bytes and reduced the prefix from 23 to 5; reusing either
long-lived named vector local lost 3,347.69 fuzzy-weighted bytes and introduced
another reference mismatch. A second nine-variant ring-child ordering sweep in
`ring-child-order-mutations.json`
(`spec_sha256=d3f9df74a23ec30c1a5a0ab021f789154ca4bd6496e62ee3ab93570ab418a761`)
found the paired collision stores byte-neutral, while moving the typed tint
copy to any later plausible boundary lost 58.00 to 62.46 fuzzy-weighted bytes.
All 15 variants were evaluated with no truncation; neither sweep produced a
winner, so the source remains unchanged.

## Spawn-slot index-order sweep

A fresh live Binary Ninja read from target
`3023:2:9499448411019345244` isolates a small scheduling difference between
the adjacent `0x07` and `0x08` spawn-controller bodies. After the allocator
call, native template `0x07` stores the returned slot at
`creature+0x78` at `0x0043230e` before forming the scaled table index at
`0x00432311`; template `0x08` performs the same two operations in the opposite
order at `0x00432351..0x00432354`. Both then initialize the same scheduler
fields and join the shared suffix at `0x00432377`, so this is a bounded
compiler-scheduling question rather than missing scheduler behavior.

The schema-1 spec `spawn-slot-index-order-mutations.json` tests five natural
ways to express template `0x07`'s allocator result, creature link, block-local
index, and scheduler pointer. Spec SHA-256 is
`624ee1b8c7a9f68611a7a0402e4fe8c00228d6feb1c0e7844b82cf25ed280f01`;
the tested source SHA-256 is
`6626bda0144efc4d68ae07e57db804822991d93691d85295bbc7885000157ad0`.
The recorded sweep evaluated all 5/5 possible one-site variants without
truncation. Every variant was byte-identical to the 86.9304% baseline:
3,161/3,159 instructions, a 23-instruction prefix, and `352/0/1` references.
No single mutation improved, so no interaction sweep was warranted and the
shared native-grounded scheduler macro remains unchanged.

## Recovery classification

This scratch is `semantic-complete` with a `compiler` residual. A
fresh live Binary Ninja pass retains all 260 native blocks, every template
handler from `0x00` through `0x43` (with `0x02` taking the native fallback),
the shared root initialization, and the complete effect, difficulty, Hardcore,
and retry tail. The sole masked-reference mismatch is the compiler-generated
retry jump table, whose candidate offsets
`0x35eb/0x361d/0x364f/0x367e` and native offsets
`0x35da/0x360c/0x363e/0x366d` cover the same four cases with a uniform
17-byte code-layout displacement. Relative to their dispatch instructions at
candidate `0x35e4` and native `0x35d3`, all four entries have identical
`+0x07/+0x39/+0x6b/+0x9a` displacements. The audited table therefore carries no
independent source-reference debt and remains visible as `352/0/1` rather than
being hidden behind an alias. The first mismatch remains the evidenced
root-offset/zero-vector local slot permutation shown above; no gameplay source
is missing there.

## Function-local declaration-order sweep

A recorded eight-variant sweep tested whether the opening low-slot permutation
was controlled by lexical declaration order. `local-declaration-order-
mutations.json` moved the creature pointer before and among the root/child
indices, moved the named aggregate after the scalars, reversed the loop-index
declarations, and grouped the scalar declarations. All 8/8 variants compile
byte-identically to the 86.9304% baseline with the same 23-instruction prefix,
3,161/3,159 instruction shape, and `352/0/1` references. The spec SHA-256 is
`760c800cffb12153d0617a418f3cbda73ad4ed7a803dd6cb976f2a8526cef0d8`.

This rules out ordinary function-local declaration order as the control for
the native `[esp+0x10..0x18]` rotation. VC6 is assigning those slots from the
root-offset and zero-vector use lifetimes, so the canonical declarations remain
unchanged rather than adding an explicit byte-offset local.

## Tint tail-merge sweep

A live Binary Ninja and normalized-listing audit localizes the 17-byte
reference displacement to one compiler suffix-folding decision. Native
template `0x3f` copies tint B at `0x00433f52`, loads tint A at
`0x00433f55`, then jumps from `0x00433f59` to the byte-identical
template-`0x2b` suffix at `0x0043382a`. The candidate instead emits the
remaining tint-A copy, size, damage, and common-tail jump in place. Those
three additional candidate instructions occupy 17 extra bytes, so every later
retry jump-table address moves by `+0x11` even though the switch topology and
all four table-entry displacements are identical.

The schema-1 spec `tint-tail-merge-mutations.json` tests natural typed-pointer,
typed-reference, and explicit-component spellings at both `0x2b` and `0x3f`.
Spec SHA-256 is
`62c14b5dcdacd66e9452c022edbade8e2710065f361542cdcf6c5ee220587ac4`.
The recorded sweep evaluates all 14/14 possible one- and two-site variants
without truncation. Thirteen variants are byte-identical to the 86.9304%
baseline, including every named pointer/reference combination. Explicit
component initialization at `0x3f` alone loses 95.62 fuzzy-weighted bytes,
drops the score to 86.2522%, and adds one candidate instruction; pairing it
with either typed-pointer spelling at `0x2b` returns to the baseline but still
does not induce the native fold.

No variant improves, so the source remains unchanged. An explicit cross-case
`goto` was deliberately excluded: it could force the compiler artifact but
would not recover additional gameplay semantics or an evidenced source-level
control-flow construct.

## Random-template RNG lifetime and store-order sweep

A new live Binary Ninja pass used the explicit `crimsonland.exe.bndb` target
`3023:2:9499448411019345244`. In the native template-`0x31` handler at
`0x0043256d..0x00432605`, the final `crt_rand` result remains in `EAX` while
the constant blue component is stored before the signed remainder conversion.
The previous source stored blue before the call and reused the function-wide
`random_heading_roll`. Giving this final tint roll a natural block-local
lifetime makes VC6 reproduce the native call/store schedule without changing
the instruction count:

```cpp
int random_tint_roll = crt_rand();
creature->color.b = 0.38f;
float random_tint_scalar =
    (float)(random_tint_roll % 0x1e) * 0.01f + 0.6f;
```

The recorded `random-roll-lifetime-mutations.json` sweep exhausts all 10/10
one- and two-site variants. This single template-`0x31` mutation improves the
weighted match by 4.461708860759 bytes, from
12,256.314240506328/14,099 (86.930379746835%) to
12,260.775949367087/14,099 (86.962025316456%), reducing the fuzzy gap from
1,842.685759493672 to 1,838.224050632913. Candidate/native instructions remain
3,161/3,159, the prefix remains 23, and references remain `352/0/1`. Pairing
the winning site with the template-`0x33` constant-store hypothesis is
byte-identical to the winner alone. The retained source SHA-256 is
`eaff2a860456d494748f96b182d26d2c372b00d631727d88e12e6997e3acf8cf`;
the mutation-spec SHA-256 is
`c29aa520b81bdfba6dcb1d52062d449a3243ac0547c009717da56794ea8692d0`.

Four additional recorded sweeps close nearby source-shape hypotheses:

- `template-28-tail-merge-mutations.json`
  (`53dab3e001ea024258a15e78ef638b2513eb1c100d9c663ebddc9dbfce62aae9`)
  evaluates all 5/5 natural helper, pointer, reference, tint-placement, and
  component spellings for the native template-`0x28` to template-`0x21`
  suffix share. Four are byte-neutral; explicit components add one instruction
  and lose 95.620047 weighted bytes.
- `random-speed-alpha-order-mutations.json`
  (`ce27d5a82827e13578f11dc7d3f6981ffe1b4bf99dedacd2f85e5b4be822a323`)
  evaluates all 5/5 template-`0x20/0x31..0x34` splits through the existing
  function-wide roll. Each adds one instruction and loses 86.698041 to
  95.620047 weighted bytes.
- `random-speed-register-lifetime-mutations.json`
  (`caaf9a8fce839f826e802e66bed1088a476b5fa26960804dcb7cf350f32edd5a`)
  evaluates register, const, and split-declaration speed-roll lifetimes at
  template `0x31`. All 3/3 produce the same one-instruction,
  91.159749-byte regression.
- `random-speed-alpha-placement-mutations.json`
  (`a737925e329c9a27d89ead4e9560e7aa14deb76c21095653ae30e85e6425fe63`)
  evaluates all 3/3 single and combined alpha-after-speed placements at
  templates `0x31` and `0x32`; VC6 canonicalizes every variant to the retained
  bytes.

The full live native disassembly used for these decisions has SHA-256
`84208879854802967cf4fe8bac46cbda58ed4464dbe111bf4f709446482b3881`.
Only the measured template-`0x31` lifetime improvement is retained.

## Raw RNG remainder-lifetime sweep

A second live Binary Ninja pass against target
`3023:2:9499448411019345244` followed the same source-level control into the
random-template cluster. The native handlers repeatedly preserve a raw RNG
result or signed remainder while one or more independent tint stores are
scheduled around `idiv`: template `0x04` at
`0x00432c0d..0x00432c44`, template `0x20` at
`0x0043287c..0x004328e1`, templates `0x03/0x05/0x06` around
`0x00432941`, `0x00432aa7`, and `0x00432cb2`, template `0x34` at
`0x004327f0..0x0043281c`, and template `0x35` at
`0x00432e18..0x00432e7d`. Replacing only the corresponding macro expansions
with natural block-local roll/remainder lifetimes reproduces more of that VC6
scheduling without changing behavior or instruction count.

The retained, fully recorded sweeps are:

- `template-04-speed-roll-lifetime-mutations.json`
  (`c7ead45d279264198059eed462ace6fd98f894909252318712cc2c0acde12340`)
  evaluates 6/6 variants and gains 17.846835443039 weighted bytes. Several
  source spellings tie at the machine-code level; the retained direct
  block-local remainder is the smallest equivalent form.
- `template-20-speed-roll-lifetime-mutations.json`
  (`79faccf9b18e4f4cbe2b20d12e370839d550c473e33227b8289d773f1d722362`)
  evaluates 5/5 variants and gains 8.923417721518 weighted bytes.
- `templates-03-05-06-speed-roll-lifetime-mutations.json`
  (`237513ef71a608d4d23cc73d7494002e773bfacd99f43d02d65e353edd352bb5`)
  evaluates all 26/26 one-, two-, and three-site variants. The three
  independently additive direct-remainder sites gain 40.155379746837 weighted
  bytes together.
- `template-20-tint-roll-lifetime-mutations.json`
  (`f2bc36de4f2a844bc7341db62eeab80881f28d7f7590cce16779ca9542779f85`)
  evaluates 5/5 variants and gains 4.461708860759 weighted bytes by keeping the
  tint roll live across the constant-blue store.
- `templates-34-35-roll-lifetime-mutations.json`
  (`565c358b961857b799044f23d44615f1700d0fbc041cef2eadb31838e9ad9615`)
  evaluates all 66/66 one- and two-site variants. The retained template-`0x34`
  tint remainder and template-`0x35` speed remainder are independently
  positive and gain 26.770253164557 weighted bytes as a pair.
- `template-35-tint-roll-lifetime-mutations.json`
  (`0487023676fd3d09de9791057e2430817cea97788e5216962f224c829010484e`)
  re-evaluates all 3/3 tint spellings on top of the retained pair and gains a
  further 4.461708860759 weighted bytes.

The same wave records four bounded negative controls. The template-`0x09`
spawn-slot sweep
(`bbf7a38dbf68a8828e3298feddc880fa9c8096d97d355eb0373dba0c76a3a4c0`,
5/5), template-`0x0f` tint/stat ordering sweep
(`0e013183db830093a09cf2986e9e89356ec2a482bffbb89a207e2992e1404efa`,
8/8), and grid-child position-lifetime sweep
(`c1ed35aea7500518ece3bc852391c2c2683ec328aa419fe9669c1d7b0b8494cf`,
8/8) find only byte-neutral or regressing shapes. The template-`0x33`
two-site roll sweep
(`b31f86a6d5d9962d90189203dc4c1ac8818b849e9a20c34977ecbcec576be3c0`)
evaluates all 15/15 combinations without a winner. In the larger
template-`0x34/0x35` matrix, all three template-`0x34` speed-lifetime
spellings add one instruction and lose 95.632046 weighted bytes, so none is
retained.

Together the nine retained lifetime seams improve this scratch by
102.619303797470 weighted bytes: from
12,260.775949367087/14,099 (86.962025316456%) to
12,363.395253164557/14,099 (87.689873417722%), reducing the fuzzy gap from
1,838.224050632913 to 1,735.604746835443. Candidate/native instructions remain
3,161/3,159, the prefix remains 23, and references remain `352/0/1`. The
retained source SHA-256 is
`3f88469321f30e59528c6d061a1402ab306d549f153db3ee27faa71b13860b16`.

## Template 0x31/0x32 speed-remainder negative control

Native scheduling around the adjacent template-`0x31` and template-`0x32`
speed rolls superficially resembles the productive block-local remainder
lifetimes above: the alpha store can sit between `rand()` and the floating
conversion. The recorded
`templates-31-32-speed-remainder-lifetime-mutations.json` sweep tests four
natural named-remainder placements at each site, both independently and in
all pairings.

All 24/24 variants were evaluated without truncation and none improves the
87.6899% baseline. Every single-site form adds one instruction and loses
about 91.176 weighted bytes; the least-bad paired form still adds one
instruction and loses 86.715 weighted bytes. References remain `352/0/1`
and the 23-instruction prefix does not move. This rules out extending the
productive remainder-lifetime pattern to these two handlers. The spec
SHA-256 is
`44ab94f6f6f1aaefffdf5749480a433fb1872e0a7787fc2cbd9a0c8bd6970ddc`;
the tested source remains
`3f88469321f30e59528c6d061a1402ab306d549f153db3ee27faa71b13860b16`.

## Grid-child tint-copy negative control

The five grid loops share a conspicuous scheduling seam around native
`0x00431b2a..0x00431b72`: VC6 loads the four-component stack tint in order but
delays the alpha store until after the child speed and reward stores. The
recorded `grid-child-tint-copy-mutations.json` sweep tested six ordinary
source forms: explicit component copies with alpha at four plausible
boundaries, a contiguous component copy, and a typed aggregate pointer.

All 6/6 variants were evaluated without truncation and none improved the
87.6899% baseline. Explicit components collapse 45 instructions across the
expanded loops and lose 374.19 weighted bytes; the typed pointer is less
disruptive but still loses 214.16. This rules out source-level component
placement as the cause of the native schedule and supports retaining the
value-object copy. The spec SHA-256 is
`e11ddf48ea48aeb4d126ad72056d5b7f8795e2122a3bc6559be25045f25416b8`;
the tested source remains
`3f88469321f30e59528c6d061a1402ab306d549f153db3ee27faa71b13860b16`.

## Grid-child vector-add boundary

A fresh native/candidate region audit isolated the repeated grid-child
position seam across all five formation handlers. Native pops the converted
vertical offset into `target_offset.y`, then reloads both target-offset
components before adding `pos`; the candidate keeps both x87 values live
through the same source expression. Four recorded, exhaustive sweeps bound
the natural recovered vector-operation shapes:

- `grid-child-vector-add-mutations.json`
  (`c60f7bb288ea78173f3ed94477672ce9695208577c15277b75e85453c6a19aa2`)
  evaluates all 11/11 operator/result variants. The only VC6-valid
  scratch-union form adds five instructions and loses 5.315 weighted bytes.
- `grid-child-vector-operator-mutations.json`
  (`7461dfefbf484d3656aa96e5fb0d916e91ece034c69a74273cfa70bb83cdf466`)
  evaluates all 17/17 constructor/operator/root-initialization combinations.
  VC6 rejects every constructor-bearing form because the modeled vector is a
  member of the scratch union; this rules out that type model rather than
  silently treating compile failures as a shape result.
- `grid-child-vector-add-out-mutations.json`
  (`9175c0798763683aa4ce88083ed9184434c8720b8efd18ad1a17d27116363644`)
  evaluates all 8/8 typed out-parameter variants.
- `grid-child-vector-alias-add-mutations.json`
  (`bf2bc231ae557b6f4a02c9188208f6b853fdf19bd9974c430e98a4246a6ac531`)
  evaluates all 14/14 mutable/const `float *` aliasing and returned-result
  variants, including the recovered `vec2_add_out` family used elsewhere.

Every valid out-parameter spelling produces the same tradeoff: it gains
48.182929 fuzzy-weighted bytes and five resolved references, but adds one
candidate instruction per grid expansion (3,166 versus native 3,159) and
still keeps the non-native x87 values live instead of reproducing the native
pop/reload boundary. The apparent score gain is therefore not retained as a
source recovery. The honest baseline remains 87.689873%, 3,161/3,159
instructions, a 23-instruction prefix, `352/0/1` references, and source
SHA-256
`3f88469321f30e59528c6d061a1402ab306d549f153db3ee27faa71b13860b16`.
