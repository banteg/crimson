# `quest_select_menu_update`

High-value recovery for the 3,436-byte quest-selection callback at
`0x00447d40`. This is the game-core Quest picker and state router, rather than
platform or rendering-backend glue.

## Recovered source shape

- derives the panel, title, five stage-icon, Hardcore-checkbox, ten-row list,
  and Back-button positions from UI element 37 with the native fixed offsets;
- constructs the complete eight-color palette, including the three colors
  retained only for native object-lifetime parity, and switches row idle/hover
  tints from blue to red while Hardcore is active;
- restores the fixed 32-by-32 stage hover rectangles, selected/unselected icon
  scale, mouse stage selection, and clamped Left/Right stage shortcuts;
- gates the Hardcore checkbox at quest unlock index 40 and forcibly clears it
  for the demo build;
- renders all ten locked/unlocked quest rows, title underlines, and the F1
  completed/games overlay. The play-count indexing intentionally preserves the
  native stage-five suffix alias documented by the modern port;
- accepts the 1 through 0 quick-select keys, mouse click, and Enter, applies the
  normal or Hardcore unlock table, and rejects the native sentinel row; and
- reproduces Back routing plus the successful quest-start transition: sign
  focus release, Quest game mode, three music mutes, selected stage copy,
  fade latch, pending Gameplay state, and UI click sound.

## Static-object evidence

The native constructor blocks use bits 1 through 128 of
`quest_select_menu_init_flags` for the row-idle, row-hover, unused-blue,
unused-dim-blue, title, selected-stage, hovered-stage, and unused-orange
colors. Bits 1 and 2 of `quest_select_screen_flags` guard the Hardcore checkbox
and Back button. PE disassembly registers the ten empty callbacks at
`0x00448b40` back through `0x00448ab0` in that construction order. The VC6
relocation table independently maps `$E2` through `$E9`, `$E11`, and `$E12` to
the same objects; `$E10` is skipped by VC6 when the second local-static guard
scope is introduced. Every named destructor scratch is an exact one-instruction
match.

## Matching evidence and honest residual

The verified VC6 build is now 803 normalized instructions against 803 native,
scores 95.8904109589041%, and audits 282 references as resolved, zero as
unresolved, and zero as mismatched. Its weighted score is
3294.794520547945/3436, leaving a 141.2054794520548-byte fuzzy gap. The broad
behavior, static-constructor sequence, and native 48-byte frame are recovered.
The remaining small regions are register/lifetime and instruction-scheduling
differences; they are recorded rather than hidden with match-only shaping.

The panel geometry now uses the recovered UI element and vertex position
aggregates in native operand order. Reordering the equivalent commutative
additions aligns the same four UI-element references without changing
behavior. Binary Ninja evidence around `0x004481cc` also shows that native adds
the selected icon's 64- and 16-pixel X offsets separately, rather than folding
them into 80. Expressing those two additions recovers the missing native
instruction and produces the small score improvement above.

The successful start path also retains the native selected-row dependency.
Disassembly at `0x00448a72..0x00448a8f` reloads
`quest_select_stage_minor_index`, increments that value, and stores it to
`quest_stage_minor`; it does not use only the equivalent local validation
copy. Expressing that dependency adds two honest candidate instructions and
slightly lowers the aggregate similarity, but recovers the native data flow
instead of preserving a scorer-friendlier local substitution.

## Bounded entry-order mutation evidence

Fresh mismatch regions and live Binary Ninja target
`3023:2:9499448411019345244` isolate the first residual to entry geometry and
stack layout. Native computes both base panel-coordinate sums before saving
EBX/EBP/ESI/EDI, spills the Y sum to `[esp+0x34]` at `0x00447d5f`, stores
`row_hovered = false` at `0x00447d63`, and only then applies the 300-pixel X
offset at `0x00447d68`. The candidate uses the same operands and values, but
has a 56-byte rather than 48-byte frame, stores the flag before spilling Y,
and colors that Y value at `[esp+0x24]`.

The schema-1 `row-hovered-init-order` sweep retained both named geometry
objects and the already-evidenced operand order. It tested only six real
declaration/initialization placements for the long-lived hover flag. The
persisted spec SHA-256 is
`9b5f94ad1375f61452383330711873d0363a49fca6bb7bbb41dda1a2b19ae981`;
the unchanged baseline source SHA-256 is
`d18ce2f4a736ae4670edc4fb028b1dae6a38780c85c2d40cbba9a0b793de3281`.
The complete harness ranking is:

| Rank | Placement | Source SHA-256 |
| ---: | --- | --- |
| 1 | entry initialized | `8e578f8facc95191485ba488518f3aa1baae1c4a2cc8c90a36e327b5e26cdae4` |
| 2 | entry declaration, assignment before panel offset | `738cddcc04efe587e270df5d7f8e37367cfb2814f9549ee8425a1e94b1d837bc` |
| 3 | split at the current position | `c9866c59cf6d6bbad2cd3179ff819280a9eb420fa1bdf51536d5950ac9cde313` |
| 4 | split before panel offset | `d4733a5cfc207d0b9c34b1d852109abf76c457fc3b881ce1b01618fbcc54b0e7` |
| 5 | initialized before panel offset | `f429b80bec17c4eeef53f0da85e86b8e119404038afb9095d2879a1fd842bef8` |
| 6 | initialized after position geometry | `7900dba61c3354a4040ae21692758eba5bf0449e83a8ebb01632aa6986400b2b` |

All six are byte-neutral: `71.15869017632241%`, 2,445.012594
fuzzy-weighted bytes, 785/803 instructions, prefix 0, `228/0/10`
references, and first target/candidate mismatch offsets `0/0`. The record has
`best_improves=false` and no winner. No positive single justified an
interaction sweep, and the semantic source remains unchanged.

## Position-copy lifetime correction

A follow-up pass combined the entry dataflow at `0x00447d5f..0x00447dbb`
with a live audit of the coherent selection-and-start tail at
`0x004487e8..0x00448aa5`. The tail confirms Back routing, mouse and 1-through-0
quick selection, Enter selection, unlock validation, and the successful
Gameplay/Quest transition already present in the source. At entry, native
forms and copies the working panel position with a lifetime consistent with
default construction followed by assignment; the previous source used copy
initialization.

The schema-1 `position-copy-shape` sweep tested four complete singles. Its
persisted spec SHA-256 is
`42a38329c1ba1fdbc848f06e19f1ed8a203956647fbbbb283432cae3049fee82`.
Default construction followed by `position = panel_position` is the only
positive result and is retained. The empty default constructor followed by
the implicit member assignment is semantically identical because both members
are assigned before use. Its source SHA-256 is
`b841f13bd49c4e41b95ff4b552672c7f8ea3d50d3a93e99274bb257dcb6a504e`.

The retained result moves from `2445.0125944584383/3436` weighted bytes
(`71.15869017632241%`) to `2475.304785894207/3436`
(`72.04030226700252%`): a gain of `30.292191435768473` weighted bytes and
`0.8816120906801062` percentage points. The gap falls from
`990.9874055415617` to `960.6952141057932`; instruction counts and prefix stay
785/803 and 0, while references improve from `228/0/10` to `235/0/5`.
Constructor-copy and both component-copy spellings regress to
`55.93434343434344%`, 781/803 instructions, and `202/0/15` references, so
they are rejected.

## Quest-name lifetime correction

Live Binary Ninja disassembly at `0x00448653..0x004486b8` shows two separate
metadata-name address calculations: native recomputes the stage/row index
before the draw call, then recomputes it again before measuring the title. It
does not keep either the prior unlock-check index or a name pointer live across
both calls.

The recorded schema-1 `quest-name-index-lifetime` sweep tested five bounded
spellings. Its spec SHA-256 is
`7abdb570d7e69c6d1c0e9e53dc856a990db5f4dcc08389a82d047d3b28b8d8c6`.
Only `recompute-index-each-use` reproduces both evidenced lifetimes well and is
retained. It raises the score from `2475.304785894207/3436`
(`72.04030226700252%`) to `2642.083907326237/3436`
(`76.89417658108955%`), a gain of `166.77912143203002` weighted bytes and
`4.8538743140870255` percentage points. The weighted gap falls from
`960.6952141057932` to `793.9160926737632`, instructions move from 785 to 794,
and the reference audit improves from `235/0/5` to `237/0/4`.

Three nearby negative sweeps are retained as evidence:

- `show-counts-lifetime` tested eight boolean spellings; the best alternatives
  were byte-neutral and direct-result forms lost 1.2115 weighted bytes.
- `row-loop-bound` tested the equivalent `row < 10` bound and was byte-neutral.
- `tenth-key-selection-lifetime` tested four order/chaining spellings for the
  `0` quick-select key; all four compiled identically to the current source.
- `unlock-mode-index-order` tested four evidenced load/index orderings; three
  were byte-neutral and duplicating the index expression lost 4.3031 weighted
  bytes.

The `minimum-stage-lifetime` sweep also demonstrates why aggregate score alone
is not an acceptance gate. A post-decrement spelling gained 45.6508 weighted
bytes, but introduced one extra instruction and three additional aligned
reference mismatches. Native `0x00448602..0x0044861a` explicitly loads the
stage, decrements that value, compares the decremented value with one, stores
it, and clamps only below one. The canonical source therefore keeps the
evidenced pre-decrement form and records the scorer-local post-decrement result
as rejected rather than writing it.

## Native row-unlock branch shape (2026-07-27)

Live disassembly at `0x00448515..0x00448631` shows the two unlock modes joining
an out-of-line unlocked-row body: Hardcore compares
`quest_unlock_index_full` with the row index, while normal mode compares
`quest_unlock_index`; either smaller value enters the locked-row body. This
first pass spelled those two native locked predicates explicitly and jumped to
the shared unlocked row otherwise.

`row-unlock-branch-shape-mutations.json` evaluated four equivalent predicate
and flag shapes. Only `locked-label` improves: it raises the weighted score
from `2642.083907326237/3436` to `2693.720726361929/3436`, a gain of
`51.63681903569204` bytes, and the ratio from `76.89417658108955%` to
`78.39699436443331%`. The instruction count remains 794. The audit changes
from `237/0/4` to `246/0/7`; all seven mismatches remain in already
nonmatching sequence alignments, while the source retains the same two proven
globals and no alias is added. The native predicate polarity and control-flow
layout, rather than aggregate score alone, support retaining the change.

The spec SHA-256 is
`e3fb276f05facc037873462e01e0f17b437075c97d62149e605bad5e22b19a8b`;
the retained source SHA-256 reported by the sweep is
`eedf5a2cfb41e68f1082671cc84b9dbfd1190a86ebd4f6190958cba9ab91bc81`.

The later `row-native-layout` sweep superseded that source spelling with the
equivalent positive `unlocked-predicate` form. It follows the target's
out-of-line body more closely, gains another 68.76297686053795 weighted bytes,
and removes no native dependency.

## Mutation-harness wave (2026-07-27)

The next bounded wave started from the retained 78.39699436443331% build
(2693.720726361929/3436 weighted bytes, 794/803 instructions, and
246/0/7 references). Each retained change was checked against live native
disassembly and written only when it preserved or corrected the recovered
behavior:

| Retained sweep | Weighted gain | Result |
| --- | ---: | --- |
| `selection-validation-lifetime/global-validation-index` | 48.20297595201737 | preserves the native global minor-index reload |
| `unlock-validation-order/byte-mode-direct-index` | 60.16760475297042 | follows the mode-byte and unlock-table load order; clears the first reference debt |
| `row-native-layout/unlocked-predicate` | 68.76297686053795 | expresses the shared out-of-line unlocked-row body |
| `back-position-lifetime/float-pair` | 98.84677923702338 | keeps the Back-button X/Y pair live across the native tail |
| `validation-inline-return/hardcore-success-goto-with-else` | 12.164273493875953 | reproduces the inline Hardcore failure epilogue |
| `entry-position-copy-offset/named-offset-plus` | 188.83952012869486 | restores the native working-vector copy and reaches 803 candidate instructions |
| `entry-x-add-order/single-expression-render-first` | 0.0 | byte-neutral, but corrects both remaining entry-reference alignments |
| `locked-row-y-argument/row-y-before-next-row` | 8.237786604472149 | reuses the native locked-row Y value and removes two redundant instructions |
| `controls-position-lifetime/named-x-y-before-x` | 94.45710754247648 | restores the long-lived controls X value and returns to 803 instructions |

The cumulative retained gain is 579.6790245720684 weighted bytes, or
16.87075158824415 percentage points. The gap falls from
742.2792736380711 to 162.60024906600256 bytes; candidate instructions move
from 794 to the native 803, and the reference audit improves from 246/0/7 to
282/0/0.

The source-order corrections are evidence-backed rather than scorer-only.
Native `0x004489f4..0x00448a31` reloads the global minor index, tests the
Hardcore mode byte, selects the corresponding unlock table, and places the
Hardcore failure epilogue inline. At entry, native materializes the temporary
`(0, 40)` offset and copies the resulting vector, then reads
`ui_element_slot_37.render_offset_x` before adding 64. Native
`0x00448543..0x0044856d` keeps the locked-row Y argument live for both text
calls, while `0x004485d4..0x004485f7` prepares Y before restoring the saved
controls X coordinate. These observations select the retained variants even
where aggregate score is tied.

All 32 sweeps are persisted in `experiments.jsonl`. Negative and neutral
records cover selection branches, vector assignment and operator spellings,
entry-panel scopes and elision, checkbox lifetime, alternate row-mode/index
layouts, row-loop tail order, color-call pointer lifetimes, Back store order,
and row/Back interactions. In particular, the locally attractive
`entry-position-adjustment/named-adjusted-y` result was rejected because it
introduced three mismatched references, and the branch-local row-mode forms
lost aggregate similarity despite matching one local load order. A compiler
profile matrix (`/G5`, `/G6`, `/Ob1`, `/Ob2`, `/Ot`, `/Oy-`, `/Os`, and `/O1`)
found no improvement over the retained `/O2 /GB /W3 /GR-` build.

## Back-position scope correction

Exact neighboring menu callbacks keep one-shot button-coordinate vectors in a
short block around the widget update. Applying that ownership boundary to the
Back position lets VC6 end its lifetime at `ui_button_update` and reuse the
native stack pair. The candidate frame drops from 56 bytes to the native 48
bytes without changing behavior, instruction count, or references. The score
moves from 95.26774595267746% to 95.8904109589041%, and the exact prefix grows
from zero to nine instructions. A fresh normalized diff confirms the former
frame-wide stack-offset residual is gone.

## Recovery classification

This scratch is `semantic-complete` with a `compiler` residual. A
fresh live Binary Ninja audit retains the complete stage-icon, Hardcore,
locked/unlocked row, Back, quick-select, validation, and gameplay-transition
paths. All 282 audited references resolve, with no unresolved or mismatched
entries. The native and candidate frames are both 48 bytes; the remaining
small register/lifetime and scheduling differences are compiler layout, not
missing menu behavior.

## 2026-08-12 current-source residual replay

The later Back-position scope correction changed the source fingerprint after
the July experiment wave, so the applicable lifetime and control-flow families
were replayed against the current 48-byte-frame source. Eighty-five bounded
single-site variants compiled across 15 current selectors. None improves the
retained `3294.794520547945/3436` weighted score (`95.8904109589041%`),
803/803 instruction alignment, nine-instruction exact prefix, or 282/0/0
reference audit.

Two new current-source matrices close the regions affected by that correction:

- `entry-hover-store-order-current-mutations.json` tests all six natural
  declaration and assignment placements around the opening panel geometry.
  Every variant is byte-identical. Native spills panel Y and then clears the
  long-lived hover flag; VC6 retains the reverse scheduling for every source
  placement without an artificial dependency.
- `scoped-back-position-shape-mutations.json` tests eight constructor, copy,
  component-order, and named-value forms inside the short Back-button scope.
  Reversing the component stores and using a named position copy are
  byte-identical. The remaining forms regress by 4 to 188 weighted bytes, and
  none reproduces native's x87 Y reload after the argument pushes.

The replay also reconfirms neutral row-loop tail, stage-clamp, tenth-key,
color-call, show-count, unlock-index, and vector-operator forms; alternate row
mode, checkbox, controls-vector, unlock-branch, and assignment shapes regress.
The residual remains a set of localized independent-store, register, and call
scheduling differences, so the `semantic-complete` / `compiler` classification
and source are unchanged.

## Original checkbox constructor recovery (2026-08-14)

The quest-select Hardcore checkbox follows the recovered 2003
`gdiCheckBox_t` constructor. Native `0x0044839d..0x004483b8` stores checked,
disabled, hover, and label in that order. The complete three-variant
`original-checkbox-constructor-mutations.json` sweep confirms that the exact
historical `disabled = checked = false` chain is byte-identical to the 95.89%,
803/803-instruction, prefix-nine, `282/0/0` baseline.

The opposite chain preserves masked bytes but worsens references to
`280/0/2`; moving the label first loses `8.557908` weighted bytes and reaches
`278/0/2`. The authenticated audit-clean chain is retained. Current source
SHA-256 is
`64ed74379946c5e3ecff30d40a44feed092bd37d46f49c33cd571fa1dad9710b`;
spec SHA-256 is
`d147e9d9f6a61fa804fc7db7ed2093c83e4858b73b79623eeeffe244b95e3088`;
the experiment ledger SHA-256 is
`a68703fff6aa2cebef322220f3a9c467b6aad93742d16b0cd3253e52dba20d52`.

## Batch 06 focused value boundaries (2026-09-05)

`batch-06-focused-value-boundaries-mutations.json` records 3 complete, compiling
controls against the 95.890411% baseline. The source forms are
`checkbox-component-assignment`, `checkbox-position-reference-owner`,
`back-position-copy-offset`.

No control improves the retained baseline without a metric tradeoff. Canonical source
and configuration are unchanged. These results bound the recorded hypothesis, not the
function's matchability.
