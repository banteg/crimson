# `controls_menu_update`

Native target: `crimsonland.exe` at `0x00448cd0` (21,289 bytes).

Live Binary Ninja disassembly and the Ghidra export recover the complete
controls-screen callback. It constructs the two buttons, three dropdowns,
direction-arrow checkbox, and 15 rebind rows; builds the configure-for,
aiming, and movement label arrays; renders both panels; and updates the three
dropdowns without losing their mutually exclusive open-state policy.

The callback copies two configured players' 13 input bindings into the live
`player_state_t::input` blocks every frame. Native code advances the config
cursor by `0x40` bytes and the player cursor by `0x360` bytes, while swapping
the stored X/Y axis order into the runtime field order. The right panel then
selects action rows from the active aim and movement schemes: keyboard torso
aim, dual-axis aim, relative/static/digital movement, point-and-click
movement, fire, and Player 1's level-up/reload bindings.

The persisted side of that copy is now a recovered
`player_input_config_t` record rather than a 64-dword array plus negative
indices. Its 13 named bindings, Y/X analog-axis storage order, and three-dword
tail account for the native 0x40-byte row stride; the destination remains the
distinct X/Y-ordered `player_input_t`.

The native loop initially materializes `config_p1_move_forward + 0x30`, the
`axis_move_x` field of the first persisted row, before incrementing the cursor
and reading the preceding row through negative displacements. Binary Ninja
therefore records the instruction-defined value at `0x004492a1` honestly as
an `int *` named `binding_axis_move_x_cursor`, rather than mis-typing that
interior cursor as the owning `crimson_cfg_t *`.

The point-and-click movement gate now uses the shared `cvar_float_t::value`
field. The matching map and live Binary Ninja database carry the same cvar
pointer type, replacing the former provisional byte-pointer-plus-`0x0c`
access. Native instructions `0x00448f94..0x00448fb1` compare the value with
zero before materializing the default count of three, then overwrite it with
four only for the nonzero case. Expressing that decision as an explicit
zero/else branch restores the complete native gate while preserving the
original behavior for signed zero and NaN.

Live Binary Ninja also shows that widget construction uses a 15-entry
countdown/pointer walk, followed by a separate pointer reset walk. Keeping
those cursors distinct from the 13-row key-label index restores the native
local lifetimes. The configured-binding lookup now advances its own index
alongside the row index instead of recomputing their sum, and the right-panel
base is constructed before the two-player runtime copy as in the native
schedule. The active rebinding row displays the native `"???"` placeholder.

Key rebinding waits for all input to be released, accepts keyboard, mouse,
joystick, and raw-input codes, and uses a separate analog-axis capture path
for the four axis rows. That path records absolute peaks for Grim IDs
`0x13f`, `0x140`, `0x141`, `0x153`, `0x154`, and `0x155`, then commits the
first peak above `0.5`. Escape cancels either capture path and releases the UI
input lock.

The native function inlines the complete `input_key_name` policy four times:
once inside the 13-row player-binding loop, once for the generic configured
binding at row 13, once for Level Up, and once for Reload. Live Binary Ninja
places the extra body after the loop at `0x0044a2c2`, assigns its label at
`0x0044b02d`, and only then enters the Level Up body at `0x0044b045`. The
scratch shares that policy through
`tools/match/include/input_key_name_impl.h`; defining
`CONTROLS_INLINE_KEY_NAME` gives VC6 the same force-inlined source body while
the standalone scratch continues to compile it as `input_key_name`.

The remaining tail now follows the native dataflow rather than helper-level
equivalences: rebind capture writes the selected regular, Level Up, or Reload
configuration field directly; the analog peak scan walks seven contiguous
float slots with a pointer, mapping the first six and routing the cleared
seventh slot through the native switch default; dropdown selection returns the
selected index; and list enable flags are reset and then cleared in native
open-list order. The two capture prompts share one base Y value, as in the
native branch join.

The panel geometry now uses the same inline vector-addition shape recovered in
the neighboring menu callbacks. The left base adds the widget position and
vertex vectors and applies `(300, 40)` before folding in the render offset.
Live disassembly at `0x00449238` shows the corresponding right base adding
`(50, 40)`, preserving a copy, applying `render_offset_x - 64`, and then
adding 32 to Y and 64 to X. A later live trace at
`0x0044936e..0x0044946d` proves that native then advances the working X by 16
and replaces the working Y with `y + 4 - 38` before drawing the
`"Configured controls"` heading. Those two operations were missing from the
scratch and are now restored explicitly.
Later, the post-heading position is staged as `y + 26` and `x - 8` before
rebuilding the key labels, followed by the native `x - 14` at `0x0044cb51`.
The inlined heading advances Y by 18 before X by 8, and its tint local is
populated in native R/B/G order before the alpha write.

The rebinding tail now follows the native branch layout more closely. Regular
player bindings are handled before the Level Up/Reload fields, the configured
binding cursor advances as its value is read, and clicking a row toggles the
capture slot directly instead of materializing an equivalent `was_idle`
boolean. The direct toggle also restores the native long-lived zero register,
which extends the exact prefix through all five widget constructors and the
selection-refresh block. The three dropdown updates pass their temporary
offsets by const reference, avoiding the redundant by-value copies that do not
exist in the native inlined call sites.

`point-click-gate-mutations.json` records the bounded schema-1 search used to
check that source recovery. The spec SHA-256 is
`0e14fa1f7f74e845215210c332a5cbc2acc6c966947a0a3399b7db286ada9afa`;
the recorded `experiments.jsonl` SHA-256 is
`cc6b2ebd715d425e6bb152558704ac2e3db7c41ad2ee58ee94249a5e2a56c114`.
All seven one-site alternatives were evaluated:

| Rank | Alternative | Source SHA-256 | Fuzzy delta | Match delta | Prefix | References |
| ---: | --- | --- | ---: | ---: | ---: | --- |
| 1 | `staged-cvar-value` | `2ec43537422e079041688be68814eda7c31e1f1de3e5e3fe4df1a903b6c119cc` | +7.875335 | +0.036993 pp | 162 | 1,530 / 4 / 9 |
| 2 | `explicit-zero-else` | `bf7923db70d879f0c87c660d7e0a27480595fa5916ab758b8787f9db10308cc2` | +7.875335 | +0.036993 pp | 162 | 1,530 / 4 / 9 |
| 3 | `staged-cvar-pointer` | `5479720b2e24fbba79088797b42d8b524b4c41004e87b1b093cf5f8b3eb7474a` | 0 | 0 pp | 148 | 1,529 / 4 / 9 |
| 4 | `implicit-float-condition` | `2d71d698a4bfa0fa4fb4366ee18e4312f8ad2e23d4a33220ed3f62fb709dcc9d` | 0 | 0 pp | 148 | 1,529 / 4 / 9 |
| 5 | `conditional-expression` | `06e494bb5febc5d5b2ece323e332b347c04a6edcaf0a4b5b614e8f80fdd17119` | -3.937668 | -0.018496 pp | 151 | 1,528 / 4 / 9 |
| 6 | `staged-nonzero-condition` | `635eaae7a12940a952d5b16c98ffcc23a6c9c32ead97355e9d38179fb131f3b6` | -7.536459 | -0.035401 pp | 151 | 1,529 / 4 / 9 |
| 7 | `reverse-default` | `826549805b411804b644799215a3549449599c676aa1052ab2d5c5eac0f3d12f` | -7.875335 | -0.036993 pp | 148 | 1,528 / 4 / 9 |

The first two alternatives compile identically, moving the first mismatch
from byte `0x2c4` to `0x30c`. The explicit branch was retained because it
captures the native decision without introducing a source-only local; the
canonical source SHA-256 is therefore the rank-2 hash above. All alternatives
replace the same source span, so they are mutually exclusive and no
positive-single interaction exists to sweep.

## Player-item publication ordering

Live native disassembly publishes the four-entry stack array through
`controls_player_profile_list.items` before filling its four slots.
`player-item-publication-mutations.json` evaluated four declaration,
initialization, and publication spellings. Publishing the pointer before the
four scalar stores is the unique improving shape and is behavior-preserving:
no consumer runs until after all stores and `item_count` is assigned.

The retained form adds 19.69 fuzzy-weighted bytes, five resolved references,
and two exact prefix instructions. Native and candidate now agree through the
publication and all four item stores; the first residual is the following x87
temporary, stored at native `[esp+0x30]` versus candidate `[esp+0x18]`.

Before the geometry/staging mutation wave below, the MSVC 6.5
`/O2 /GB /W3 /GR-` result was **76.72%**, with a fuzzy gap of
4,955.55 bytes, 164 exact prefix instructions, 5,421 native instructions
versus 5,392 candidate instructions, and reference audit **1,535 resolved /
4 unresolved / 9 mismatched**. This improves the earlier **76.59%** result
(4,983.12-byte gap, 148 exact prefix instructions, 5,392 candidate
instructions, and 1,529 / 4 / 9 references) while retaining the native
`0x74`-byte frame. The remaining gap is dominated by allocation and early
UI/x87 lowering around the four enormous equivalent inlined key-label bodies.
All observed widgets, labels, scheme branches, runtime binding copies, row
updates, capture rules, and dropdown writes are present; no fake dependency,
padding, volatile coercion, or inline assembly is used.

## Opening x87 lifetime sweeps

Live disassembly evaluates the left-panel X/Y sums across publication of the
four player labels. `vector-add-return-mutations.json` tested six constructor,
named-result, field-result, and component-order forms. Natural component order
and named scalar components are byte-identical; materializing a result object
regresses by 283 to 303 fuzzy-weighted bytes.

`left-panel-lifetime-mutations.json` then evaluated six complete geometry and
player-item declaration orders. Four compile byte-identically. Scalarizing the
offset extends the exact prefix by eight instructions but loses 11.81 weighted
bytes and one reference overall; fully scalarizing the anchor loses more.
Neither sweep improved that 76.72% baseline, so the recorded negatives bound
the opening mismatch without source churn.

## Native geometry correction and vector-staging mutation wave

The next wave started by rechecking the opening and right-panel dataflow in
live Binary Ninja target `3023:2:9499448411019345244`. Native
`0x004492a1..0x0044931d` walks the configured bindings from
`input_config[0].axis_move_x`, writes 13 fields into each live
`player_state_t::input`, swaps stored X/Y into runtime Y/X order, advances the
source by `0x40` and destination by `0x360`, and uses a signed loop bound. The
retained typed `int *` cursor reproduces that ownership without raw byte
offsets. Native widget initialization at `0x00449484..0x00449499` also stores
`hovered` before `activated`; restoring that field order is independently
positive. Together these two small, recorded changes added 11.81
fuzzy-weighted bytes before the larger geometry work.

The live right-panel trace at `0x0044936e..0x0044946d` exposed a real source
recovery error rather than a compiler residual: after staging the right base,
native adds 16 to X and computes `y + 4 - 38` before drawing
`"Configured controls"`. The scratch omitted both operations. Restoring them
initially lowers the aggregate score because it perturbs the enormous
function's allocation, but it is required by the native semantics. The
complete constructor form in
`right-heading-complete-preadjust-mutations.json` then recovers 283.20
fuzzy-weighted bytes relative to that corrected intermediate. Reversing the
right-position/right-base ownership to match the native two-vector staging
adds another 16.19 weighted bytes; several natural spellings compile
identically, so the simplest evidence-backed form is retained.

The highest-leverage result comes from the left panel. Native
`0x00448fbb..0x00449074` materializes the adjusted left base and then copies
both components into the draw-position local before the first textured-quad
call. The scratch had collapsed those objects. The complete six-variant
`left-draw-position-staging-mutations.json` sweep found a unique natural
winner, `copy-after-adjust`: it restores the three missing copy instructions,
adds **734.73 fuzzy-weighted bytes**, improves the reference audit by two
mismatches and three resolved references at that checkpoint, and requires no
volatile storage, padding, dummy dependency, raw offset, or register forcing.
That native-grounded staging is retained.

Several complete negative searches constrain the remaining opening residual:

- `right-heading-geometry-mutations.json` and
  `right-heading-existing-local-mutations.json` evaluated seven alternatives
  each while isolating the recovered coordinate operations.
- `item-reset-bound-mutations.json` evaluated all six direct/member-bound
  spellings. Removing the extra loop instruction caused a much larger
  allocation collapse.
- `runtime-item-bound-interaction-mutations.json` evaluated all seven singles
  and pairs across the runtime-copy and item-reset bounds; no interaction
  improved the retained source.
- `right-outline-position-mutations.json` completed all 15 singles and pairs
  for outline and row-start construction; its best result still lost 3.93
  weighted bytes.

The complete sweeps are recorded in `experiments.jsonl`; its SHA-256 is
`802926d57dce9ebb81f8b5fea321cd418be86547b4079b4f617a47cff623eb5d`.
The principal retained specs have SHA-256
`2570be67d39faa840b30f09745d1be1ff2100d28c69d646096884847f4f7cdb6`
(runtime copy),
`5ff9f46e9a43810dbfebd3e3db2e9295cc409620ff51a1e7a86730ae566a8a8b`
(item order),
`bbb72d87ba070a3767777fa8b37055114b5a66223a97b2e4381f9e4c144bff95`
(complete heading preadjust),
`4080f35f412acb83528b303aa3c0cce196a2def32b1402063af39d477c009885`
(right-base staging), and
`3f6b04f779999102d9452c4f4fb019e8d37cad3687359144c437348d90f47695`
(left draw-position staging).

The retained source SHA-256 is
`e058ee5ca4a0a759954180b63e6e655443fba76097ec3c2e99f31b31f1d38133`.
It now matches **80.1625%**, with a fuzzy gap of **4,223.1965 bytes**, 164
exact prefix instructions, 5,421 native instructions versus 5,407 candidate
instructions, and reference audit **1,540 resolved / 4 unresolved / 9
mismatched**. Relative to the pre-wave 76.7225% canonical result, this is a
**3.4401 percentage-point** gain and about **732.35 recovered weighted
bytes**, while also correcting the missing native right-heading coordinates.

## Current opening-lifetime replay

The existing left-panel lifetime menu was replayed against the current post-staging source. None of its six variants improved the 80.1625% baseline: four were byte-identical, one lost 11.80 weighted bytes, and the scalar form lost 1027.28. Recorded spec SHA: `cdfbe1fe76105490210d88db25c68fc2ba835282030c48eb94b63f604cc267ae`.

A second five-variant sweep predeclared and regrouped the player-item publication and opening vectors. All five variants were byte-identical, showing that these opening locals are also placed from use sites rather than declaration order. Recorded spec SHA: `34e1998c665348f26f8300c2c1ce4d731914ef5fc75bcead329dec5061cc4c93`.

## Runtime-binding symbol-anchor negative

The persisted and live input-record layouts were re-audited before another
mutation pass: `player_input_config_t` is `0x40` bytes with `axis_move_x` at
`0x30`, while `crimson_cfg_t::input_config` begins at `0x1c8`. The candidate's
apparent `config_blob + 0x1cc` base is therefore VC6 induction-variable
rebasing to `move_key_backward`, not a bad field offset.

`runtime-binding-symbol-anchors-mutations.json` tested five typed and
linker-symbol source/destination cursor spellings around that copy. Every
variant preserves the 164-instruction prefix but loses at least 1,000.27
fuzzy-weighted bytes; the best falls from 80.16% to 75.46%. The named aggregate
anchors are not the missing source shape, so the typed interior cursor remains
canonical.

## Native capture and publication-order wave

Live Binary Ninja evidence from target `3023:2:9499448411019345244` grounded
another bounded pass through the axis-capture and player-selection tail. The
wave started at **80.1625%**, 17,065.80 fuzzy-weighted bytes, 5,407/5,421
instructions, a 164-instruction exact prefix, and reference audit
1,540/4/9.

Four natural source changes are retained:

- `axis-peak-scan-loop-mutations.json` evaluated all 15 single and pair
  variants. The complete prechecked `while` form is safe because the cursor
  starts below the fixed seven-float end, and it recovered 14.17 weighted
  bytes while removing four candidate instructions.
- Native `0x0044d867..0x0044d98b` subtracts 27 pixels before the prompt and
  restores them at the join before activation scanning. The scratch omitted
  the restore. Both natural addition spellings in
  `prompt-x-restore-mutations.json` recovered 7.07 weighted bytes and one
  reference; the compound assignment is retained.
- Native stages the prior-slot test, clears the slot, and assigns the current
  row only when the prior slot was inactive. Reversing the equivalent source
  branch in `rebind-activation-toggle-mutations.json` recovered 3.93 weighted
  bytes. Boolean/default staging variants caused large allocation regressions
  and were rejected.
- Native `0x0044dfca..0x0044dfeb` publishes the profile selection and rebind
  player before the derived aim and move selections. The matching simple
  order in `player-selection-publication-mutations.json` recovered 7.87
  weighted bytes and two references. Reversing the profile/player stores
  worsened the reference audit, and reversing aim/move was neutral.

The in-place sign-bit masking visible in the native axis helper was also
tested directly. All six variants in
`axis-peak-absolute-value-mutations.json` were replayed against both the
original and retained loop shapes. The best natural in-place forms lost
23.60 weighted bytes, and the more staged forms lost substantially more, so
the current value-return helper remains canonical. All matrices completed
without budget truncation; the negative results are retained as codegen
evidence rather than source churn.

The final retained source SHA-256 is
`082e491da02ce7e642faf01abe6face27849b7da35fb30f167e99d09835ab0db`.
It matches **80.3177%**, with **17,098.84 fuzzy-weighted bytes** and a
**4,190.16-byte fuzzy gap**, 5,406 candidate instructions versus 5,421
native instructions, the same 164-instruction exact prefix, and reference
audit **1,543 resolved / 4 unresolved / 9 mismatched**. This slice recovered
33.04 weighted bytes and three references without coercive constructs.

Recorded spec SHA-256 values:

- axis absolute-value shape:
  `778eb5887be61af9c07ad366b9d6134cd5c3373991162df78bf8720cf2452e2e`;
- axis peak-scan loop:
  `6c0bbd6c017a1cc264951adb3749c28714e55398ece30c8f43e35b8e9aec5943`;
- prompt X restore:
  `909aa6f52822dc8d8492b9777df5ecd249b36abc7d871623ab267c6a5efc0675`;
- activation toggle:
  `388ef7ccd292caa70d195438cda24676292fd5cb4f1e9a704618ce0268ef479e`;
  and
- player-selection publication:
  `15cf4b14ef2ecbee354da6a3f0556fc88bfa880751404cecac67929e3a9578a2`.

The updated `experiments.jsonl` SHA-256 is
`728d942aeb826d66779c3dc67bfe419fa75af5d8a53404c6042f300c0336ad1c`.

## Right-coordinate lifetime refinement

Live Binary Ninja disassembly at `0x0044936e..0x004493a6` shows the right
panel evaluating `y + 4` before `x + 16`, then subtracting 38 from the staged
Y coordinate around the white-color call. The complete eight-variant
`right-adjusted-coordinate-lifetime-mutations.json` sweep tested scalar,
vector, field, and direct compound-assignment lifetimes for that schedule.
The unique best form keeps the pre-subtraction Y value in a scalar while
updating X in the existing base vector. It is behavior-preserving and
recovers **11.80 fuzzy-weighted bytes** without changing the 5,406-instruction
candidate, exact prefix, unresolved references, or mismatched references.
The clean resolved-reference count changes from 1,543 to 1,542.

The retained source now matches **80.3731%**, with **17,110.64
fuzzy-weighted bytes** and a **4,178.36-byte fuzzy gap**, 5,406 candidate
instructions versus 5,421 native instructions, a 164-instruction exact
prefix, and reference audit **1,542 resolved / 4 unresolved / 9
mismatched**.

Three complete matrices were replayed after the changed local lifetime:

- all 15 outline/row-start singles and pairs remained negative; the nearest
  variant lost 3.93 weighted bytes;
- all five opening vector declaration orders remained byte-identical; and
- four of six left-panel lifetime variants remained byte-identical, while
  the two scalar forms lost 23.60 and 1,027.36 weighted bytes.

This covers all 26 planned post-win variants without budget truncation. A
compiler-profile sweep also leaves stock MSVC 6.5 and 6.6 tied at the retained
result; MSVC 6.0 and the Processor Pack regress materially, while MSVC 7 does
not compile this scratch.

The retained source SHA-256 is
`9b0c0387901cdf3403587e0da7a3857214ade111eedca09580d0484c07a34a5c`.
The new coordinate-lifetime spec SHA-256 is
`83ad5aa51866b438651f6d48378b33f2755bc8f4003877c5a6d0ee4b340612fa`;
the replayed outline, opening-declaration, and left-panel spec SHA-256 values
are `86b57632d8e22f4f0ccce380ae6a7729964fb6256cd2feeb7d064c548a5307df`,
`34e1998c665348f26f8300c2c1ce4d731914ef5fc75bcead329dec5061cc4c93`,
and `cdfbe1fe76105490210d88db25c68fc2ba835282030c48eb94b63f604cc267ae`.
The updated `experiments.jsonl` SHA-256 is
`1ad3a6e82f40c9b8f237cc1b6e99a164f8ad29ab4b4342367da6509e805cbad8`.

## Active-row reload and tint-aggregate recovery

This wave started from **80.3731%**, 17,110.6380 fuzzy-weighted bytes, a
4,178.3620-byte fuzzy gap, 5,406/5,421 candidate/native instructions, a
164-instruction exact prefix, and reference audit 1,542/4/9.

Live Binary Ninja target
`3023:2:9499448411019345244` shows that native
`0x0044cb06..0x0044cb4a` indexes `controls_rebind_items` directly. It reloads
`controls_rebind_slot_index` after `crt_free`, scales the reloaded index, and
keeps that scaled offset across `strdup_malloc`. The old scratch instead held
an item reference across both calls. All four natural access shapes in
`active-rebind-row-access-mutations.json` improved the aggregate score, but
direct repeated indexing is the unique native instruction-for-instruction
shape. It recovers 28.2946 weighted bytes, adds two native instructions, and
changes the reference audit from 1,542/4/9 to 1,546/4/8.

The adjacent native block at `0x0044cb51..0x0044cb97` loads tint R, B, and G,
writes global alpha `0.7`, reloads alpha, and then publishes the local color.
This is naturally explained by the contiguous global color aggregate already
used by neighboring recovered UI code: assign its alpha field, then copy the
aggregate into the local heading tint. The complete ten-variant
`section-tint-publication-mutations.json` sweep confirms that
`alpha-first-aliased-aggregate-copy` is the unique best form. It recovers a
further 45.5953 weighted bytes, adds the one missing instruction, and improves
the reference audit to 1,550/4/7.

Together the retained changes make the normalized candidate exact from the
native instruction at `0x0044cafb` through `0x0044cbea`; the next mismatch is
the first heading line-offset stack slot at `0x0044cbef`.

Four complete negative matrices bound nearby residuals:

- `entry-alignment-interactions-mutations.json` evaluated all 19 runtime-copy
  and item-reset singles and pairs. Two variants are byte-identical; the
  native-looking early cursor schedules lose at least 1,018.54 weighted
  bytes, and the interior-byte reset forms lose at least 3,699.32.
- `heading-line-local-lifetimes-mutations.json` evaluated all eight
  declaration and initialization placements for the repeated `(0, 13)`
  heading vector. Four are byte-identical and four regress, proving that its
  remaining stack-slot difference comes from broader function allocation.
- `axis-peak-bit-scalar-mutations.json` evaluated six scalar, union, and
  direct sign-bit-mask spellings. Two are byte-identical; the variants that
  add the missing tail instructions still lose at least 143.90 weighted bytes
  and 29 resolved references.
- `axis-peak-bit-selection-mutations.json` evaluated six combinations of the
  scalar bit temporary with branch and conditional selection shapes. Every
  variant regresses; the nearest loses 54.23 weighted bytes.

All 53 planned variants completed without truncation. The retained source now
matches **80.7202%**, with **17,184.5280 fuzzy-weighted bytes** and a
**4,104.4720-byte fuzzy gap**, 5,409 candidate instructions versus 5,421
native instructions, a 164-instruction exact prefix, and reference audit
**1,550 resolved / 4 unresolved / 7 mismatched**. This is a net recovery of
73.8899 weighted bytes and two reference mismatches from the starting point.

The retained source SHA-256 is
`c44122e1e1e2f007f6dc5843c72960c57354ff7df461eb325ee3b812802e3487`.
The recorded spec SHA-256 values are
`40e1cf31137f7cf327c325fcb728fa7a47ff640b2e7177da54c2e011d83a2cda`,
`daf069b49199ab58086bde73a95b2865d6799a00938d34434f0ee5bc1ada1ef3`,
`d75e006bab6e2edff097ba4adec19c21537022ac8de9516933d80b711e99cd77`,
`8c15f8b1f5b4f59416e2a723b1758e837b8c0243cd08ba2762c2d3f6a78129aa`,
`e67c1557d747cc275714371ca0ac3809bd1cfbff5c3194c6fad1f990508b2743`,
and
`746641895ba65e4f8aa645ff24d44519b47117af79ac1b0d392c0ed12fc5b2da`.
The updated `experiments.jsonl` SHA-256 is
`7aaf689d28864fa1f3b83dcc710e476a56e595363c5dfcff5f5a96646819e9ac`.
