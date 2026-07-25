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
match=82.22% prefix=26/3159 target_insns=3159 candidate_insns=3136 refs=351/0/1
first_target=mov dword [esp+0x18], esi
first_candidate=mov dword [esp+0x10], esi
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
